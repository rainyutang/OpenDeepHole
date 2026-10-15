"""Optional results remain distinguishable from absent or inaccessible scans."""

import asyncio

import pytest

from backend.api import scan
from test_scan_sharing import client_for, create_share, environment


@pytest.mark.parametrize("resource", ["threat-analysis", "fp-review/overview"])
def test_optional_result_contract_across_access_modes(environment, resource):
    env = environment
    with env.store._lock:
        env.store._conn.execute("DELETE FROM fp_review_jobs WHERE scan_id = ?", (env.scan_id,))
        env.store._conn.commit()

    async def run():
        async with client_for(env) as client:
            token = await create_share(client, env)
            owner_prefix = "/api/scan" if resource == "threat-analysis" else "/api/v2/scans"
            routes = [
                (f"{owner_prefix}/{env.scan_id}/{resource}", {}, env.tokens["owner"]),
                (f"/api/public/scans/{env.scan_id}/{resource}", {"token": env.meta.public_access_token}, {}),
                (f"/api/shared/scans/{env.scan_id}/{resource}", {"token": token}, {}),
            ]
            for url, params, headers in routes:
                for legacy_params in (params, {**params, "allow_missing": "false"}):
                    response = await client.get(url, params=legacy_params, headers=headers)
                    assert response.status_code == 404, response.text
                    assert response.json()["detail"].startswith("No ")
                response = await client.get(url, params={**params, "allow_missing": "true"}, headers=headers)
                assert response.status_code == 200, response.text
                assert response.json() is None
                denied = await client.get(
                    url, params={**params, "token": "wrong", "allow_missing": "true"},
                    headers=env.tokens["other"] if headers else {},
                )
                assert denied.status_code == 403, denied.text
                missing = await client.get(
                    url.replace(env.scan_id, "missing-" + env.scan_id),
                    params={**params, "allow_missing": "true"}, headers=headers,
                )
                assert missing.status_code == (404 if "/api/public/" in url else 403), missing.text

            # Admin and cached owner access bypass the ordinary ownership query;
            # neither may turn a missing parent scan into an empty 200 response.
            missing_url = routes[0][0].replace(env.scan_id, "missing-" + env.scan_id)
            missing = await client.get(missing_url, params={"allow_missing": "true"}, headers=env.tokens["admin"])
            assert missing.status_code == 404, missing.text
            assert missing.json()["detail"] == "Scan not found"
            scan._scan_owners["missing-" + env.scan_id] = env.meta.user_id
            missing = await client.get(missing_url, params={"allow_missing": "true"}, headers=env.tokens["owner"])
            assert missing.status_code == 404, missing.text
            assert (await client.get(routes[0][0], params={"allow_missing": "true"})).status_code == 401

            if resource == "threat-analysis":
                artifacts = {
                    name: {"path": name + ".json", "content": content}
                    for name, content in (
                        ("value_asset_path", []), ("high_risk_modules_path", []),
                        ("attack_tree_path", {"attack_trees": []}),
                    )
                }
                expected = {"entrypoint_result": {"result": True, **{
                    name: item["path"] for name, item in artifacts.items()
                }}, "artifacts": artifacts}
                env.store.replace_threat_analysis(env.scan_id, expected)
            else:
                env.store.create_fp_review_job(env.review_id, env.scan_id, 0, env.status.created_at)
                expected = env.store.get_fp_review_overview(env.scan_id).model_dump(mode="json")
            for url, params, headers in routes:
                for current_params in (params, {**params, "allow_missing": "true"}):
                    response = await client.get(url, params=current_params, headers=headers)
                    assert response.status_code == 200, response.text
                    assert response.json() == expected

    asyncio.run(run())
