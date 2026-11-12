import axios from "axios";

export function isInvalidTaskCursorError(error: unknown): boolean {
  return axios.isAxiosError(error) && error.response?.status === 400 && error.response.data?.detail === "Invalid cursor";
}

/** Older servers still return explicit absence errors for optional scan results. */
export function isMissingOptionalResult(error: unknown, details: readonly string[]): boolean {
  return axios.isAxiosError(error) && error.response?.status === 404
    && details.includes(error.response.data?.detail);
}
