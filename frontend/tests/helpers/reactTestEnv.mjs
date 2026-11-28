import { act } from "react";
import TestRenderer from "react-test-renderer";

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

export { act };
export const { create } = TestRenderer;
export default { ...TestRenderer, act, create: TestRenderer.create };
