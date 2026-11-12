
from datetime import datetime, timezone
from deephole_client.fp_review import (
    build_fp_review_method_catalog,
    discover_fp_review_method_manifests,
    load_fp_review_methods,
    runtime as fp_runtime,
)
from pathlib import Path
from unittest.mock import Mock, patch
import tempfile
import unittest
import backend.scans.configuration as backend_scans_configuration
import backend.scans.fp_review_policy as backend_scans_fp_review_policy
import backend.scans.report_records as backend_scans_report_records
from backend.application import ApplicationError as HTTPException, get_runtime
from backend.models import (
    CreateScanRequest,
    FpReviewMethodCatalog,
    FpReviewMethodSelection,
    FpReviewResult,
    FpReviewStageConfig,
    ScanItemStatus,
    ScanMeta,
    ScanStatus,
    Vulnerability,
)
from backend.store.sqlite import SqliteScanStore


def _write_method(
    root: Path,
    method_id: str,
    *,
    default: bool,
    max_concurrency: str = "2",
    entry: str = "async def run(**kwargs):\n    return {'status': 'cancelled'}\n",
) -> None:
    directory = root / method_id
    directory.mkdir(parents=True)
    (directory / "method.yaml").write_text(
        "\n".join([
            f"label: {method_id}",
            "description: test method",
            f"default: {'true' if default else 'false'}",
            f"max_concurrency: {max_concurrency}",
            "stages:",
            "  - key: verify",
            "    label: Verify",
            "documents: []",
            "",
        ]),
        encoding="utf-8",
    )
    (directory / "method.py").write_text(entry, encoding="utf-8")


def _vulnerability(name: str) -> Vulnerability:
    return Vulnerability(
        file=f"{name}.c",
        line=10,
        function=name,
        vuln_type="out_of_bounds",
        severity="high",
        description=f"{name} issue",
        ai_analysis="analysis",
        confirmed=True,
        ai_verdict="confirmed",
    )


class FpReviewMethodDiscoveryTests(unittest.TestCase):
    def test_repository_catalog_discovers_builtins_and_manifest_metadata(self) -> None:
        catalog = build_fp_review_method_catalog()

        self.assertEqual(catalog["errors"], [])
        methods = {item["method_id"]: item for item in catalog["methods"]}
        self.assertEqual(set(methods), {"adversarial", "fp_check"})
        self.assertTrue(methods["adversarial"]["default"])
        self.assertEqual(methods["adversarial"]["max_concurrency"], 0)
        self.assertEqual(
            [stage["key"] for stage in methods["adversarial"]["stages"]],
            ["prove_bug", "prove_fp", "final_judge"],
        )
        self.assertEqual(methods["fp_check"]["max_concurrency"], 0)
        self.assertTrue(all(
            item.max_concurrency == 0
            for item in FpReviewMethodCatalog.model_validate(catalog).methods
        ))
        self.assertIn(
            "gate_review",
            {stage["key"] for stage in methods["fp_check"]["stages"]},
        )
        adversarial = load_fp_review_methods().get("adversarial")
        self.assertIsNotNone(adversarial)
        self.assertEqual(
            [path.name for path in adversarial.manifest.skill_paths],
            ["skills"],
        )
        self.assertTrue(all(
            document.path.name == "SKILL.md"
            for document in adversarial.manifest.documents
        ))

    def test_manifest_accepts_scan_capacity_and_fixed_limits(self) -> None:
        for value in (0, 1, 4):
            with self.subTest(max_concurrency=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                _write_method(root, "custom", default=True, max_concurrency=str(value))
                manifests, errors = discover_fp_review_method_manifests(root)

                self.assertEqual(errors, [])
                self.assertEqual(len(manifests), 1)
                self.assertEqual(manifests[0].max_concurrency, value)

    def test_manifest_rejects_invalid_concurrency(self) -> None:
        for value in ("-1", "true", "false", "1.5", '"0"', "null"):
            with self.subTest(max_concurrency=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                _write_method(root, "custom", default=True, max_concurrency=value)
                manifests, errors = discover_fp_review_method_manifests(root)

                self.assertEqual(manifests, [])
                self.assertTrue(any("max_concurrency" in error for error in errors))

    def test_discovery_is_strict_and_loader_requires_async_kwargs_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_method(root, "good", default=True)
            _write_method(
                root,
                "bad_entry",
                default=False,
                entry="def run(value):\n    return value\n",
            )
            invalid = root / "bad_manifest"
            invalid.mkdir()
            (invalid / "method.py").write_text(
                "async def run(**kwargs):\n    return {}\n",
                encoding="utf-8",
            )
            (invalid / "method.yaml").write_text(
                "label: bad\ndescription: bad\ndefault: false\n",
                encoding="utf-8",
            )

            manifests, manifest_errors = discover_fp_review_method_manifests(root)
            registry = load_fp_review_methods(root)

        self.assertEqual({item.method_id for item in manifests}, {"good", "bad_entry"})
        self.assertTrue(any("bad_manifest" in error for error in manifest_errors))
        self.assertIsNotNone(registry.get("good"))
        self.assertIsNone(registry.get("bad_entry"))
        self.assertTrue(any("run" in error for error in registry.errors))


class FpReviewRuntimeContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_method_receives_only_one_vulnerability_contract(self) -> None:
        loaded = load_fp_review_methods().get("adversarial")
        self.assertIsNotNone(loaded)
        captured: dict = {}

        async def run(**kwargs):
            captured.update(kwargs)
            return {
                "status": "success",
                "verdict": "true_positive",
                "reason": "reachable",
                "stage_outputs": {"prove_bug": "# evidence"},
            }

        registry = fp_runtime.FpReviewMethodRegistry([
            fp_runtime.LoadedFpReviewMethod(
                manifest=loaded.manifest,
                run=run,
            )
        ])
        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_review.runtime.load_fp_review_methods",
            return_value=registry,
        ):
            result = await fp_runtime.run_fp_review(
                method_id="adversarial",
                project_path=tmp,
                code_scan_path=tmp,
                work_dir=tmp,
                scan_id="scan-1",
                review_id="review-1",
                vuln_index=7,
                vulnerability={"index": 7, "description": "issue"},
            )

        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(captured["vuln_index"], 7)
        self.assertEqual(captured["vulnerability"]["index"], 7)
        self.assertNotIn("vulnerabilities", captured)
        self.assertNotIn("method_label", captured)

    async def test_runtime_rejects_undeclared_method_stage(self) -> None:
        loaded = load_fp_review_methods().get("adversarial")
        self.assertIsNotNone(loaded)

        async def run(**_kwargs):
            return {
                "status": "success",
                "verdict": "false_positive",
                "reason": "guarded",
                "stage_outputs": {"not_declared": "# invalid"},
            }

        registry = fp_runtime.FpReviewMethodRegistry([
            fp_runtime.LoadedFpReviewMethod(
                manifest=loaded.manifest,
                run=run,
            )
        ])
        with tempfile.TemporaryDirectory() as tmp, patch(
            "deephole_client.fp_review.runtime.load_fp_review_methods",
            return_value=registry,
        ):
            with self.assertRaisesRegex(ValueError, "undeclared stage"):
                await fp_runtime.run_fp_review(
                    method_id="adversarial",
                    project_path=tmp,
                    code_scan_path=tmp,
                    work_dir=tmp,
                    scan_id="scan-1",
                    review_id="review-1",
                    vuln_index=0,
                    vulnerability={"index": 0},
                )


class FpReviewMethodBackendTests(unittest.TestCase):
    def tearDown(self) -> None:
        get_runtime().scans.running_scans.clear()
        get_runtime().scans.scan_owners.clear()

    def test_request_defers_default_to_catalog_and_rejects_unknown_method(self) -> None:
        request = CreateScanRequest(project_path="/repo", checkers=[])
        self.assertIsNone(request.fp_review_method)

        method_id, selection = backend_scans_configuration._resolve_fp_review_method(None)
        self.assertEqual(method_id, "adversarial")
        self.assertEqual(selection.method_id, method_id)
        self.assertTrue(selection.stages)
        with self.assertRaises(HTTPException) as caught:
            backend_scans_configuration._resolve_fp_review_method("not-installed")
        self.assertEqual(caught.exception.status_code, 400)

    def test_scan_persists_dynamic_method_and_immutable_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            now = datetime.now(timezone.utc).isoformat()
            selection = FpReviewMethodSelection(
                method_id="custom",
                method_label="Custom",
                description="snapshot",
                stages=[FpReviewStageConfig(key="verify", label="Verify")],
            )
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                created_at=now,
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=0,
                processed_candidates=0,
                vulnerabilities=[],
                fp_review_method="custom",
                fp_review_method_selection=selection,
            )
            meta = ScanMeta(
                scan_items=[],
                created_at=now,
                fp_review_method="custom",
                fp_review_method_selection=selection,
            )
            store.save_scan(scan, meta)
            store.create_fp_review_job("review-1", "scan-1", 0, now, "custom")

            loaded_scan, loaded_meta = store.load_scan("scan-1")
            job = store.get_fp_review_job("review-1")
            store.close()

        self.assertEqual(loaded_scan.fp_review_method, "custom")
        self.assertEqual(loaded_meta.fp_review_method_selection, selection)
        self.assertEqual(job.method, "custom")

    def test_report_stage_titles_use_persisted_method_snapshot(self) -> None:
        selection = FpReviewMethodSelection(
            method_id="removed_method",
            method_label="Removed method",
            stages=[FpReviewStageConfig(key="custom_stage", label="Custom stage")],
        )
        store = Mock()
        store.get_scan_meta.return_value = ScanMeta(
            scan_items=[],
            created_at="2026-08-04T00:00:00+00:00",
            fp_review_method="removed_method",
            fp_review_method_selection=selection,
        )

        with patch("backend.application.default_store_factory", return_value=store):
            titles = backend_scans_report_records._fp_review_stage_titles("scan-1")

        self.assertEqual(titles, [("custom_stage", "Custom stage")])

    def test_all_methods_use_unresolved_first_then_full_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteScanStore(Path(tmp) / "scans.db")
            now = datetime.now(timezone.utc).isoformat()
            scan = ScanStatus(
                scan_id="scan-1",
                project_id="project",
                created_at=now,
                status=ScanItemStatus.COMPLETE,
                progress=1.0,
                total_candidates=2,
                processed_candidates=2,
                vulnerabilities=[_vulnerability("first"), _vulnerability("second")],
                fp_review_method="adversarial",
            )
            meta = ScanMeta(
                scan_items=[],
                created_at=now,
                fp_review_method="adversarial",
            )
            store.save_scan(scan, meta)
            for vulnerability in scan.vulnerabilities:
                store.add_vulnerability("scan-1", vulnerability)
            store.create_fp_review_job("review-1", "scan-1", 2, now, "adversarial")
            store.add_fp_review_result(
                "review-1",
                FpReviewResult(
                    vuln_index=0,
                    verdict="fp",
                    severity="low",
                    reason="guarded",
                    created_at=now,
                ),
            )
            with patch("backend.application.default_store_factory", return_value=store):
                first = backend_scans_fp_review_policy._ensure_fp_review_job_for_scan(
                    "scan-1",
                    publish_started=False,
                )
                store.add_fp_review_result(
                    "review-1",
                    FpReviewResult(
                        vuln_index=1,
                        verdict="tp",
                        severity="high",
                        reason="reachable",
                        created_at=now,
                    ),
                )
                second = backend_scans_fp_review_policy._ensure_fp_review_job_for_scan(
                    "scan-1",
                    publish_started=False,
                )
            store.close()

        self.assertEqual([item["index"] for item in first["confirmed"]], [1])
        self.assertEqual([item["index"] for item in second["confirmed"]], [0, 1])
