import { useCallback, useEffect, useState } from "react";

const ANNOUNCEMENT_LAST_SEEN_STORAGE_PREFIX = "opendeephole.announcements.lastSeen";

function announcementLastSeenStorageKey(userId: string) {
  return `${ANNOUNCEMENT_LAST_SEEN_STORAGE_PREFIX}.${userId}`;
}

function normalizeAnnouncementVersion(value: string | null) {
  if (!value || Number.isNaN(Date.parse(value))) return "";
  return value;
}

function readLastSeenAnnouncementVersion(userId: string) {
  if (typeof window === "undefined") return "";
  try {
    return normalizeAnnouncementVersion(
      window.localStorage.getItem(announcementLastSeenStorageKey(userId)),
    );
  } catch {
    return "";
  }
}

function isNewerAnnouncementVersion(candidate: string, baseline: string) {
  if (!candidate) return false;
  if (!baseline) return true;

  const candidateTime = Date.parse(candidate);
  const baselineTime = Date.parse(baseline);
  if (candidateTime !== baselineTime) return candidateTime > baselineTime;

  // Preserve Python ISO timestamps' sub-millisecond precision.
  return candidate > baseline;
}

export function useAnnouncementUnread(userId: string) {
  const [announcementOpen, setAnnouncementOpen] = useState(false);
  const [announcementRefreshKey, setAnnouncementRefreshKey] = useState(0);
  const [announcementVersion, setAnnouncementVersion] = useState("");
  const [lastSeenAnnouncementVersion, setLastSeenAnnouncementVersion] = useState(
    () => readLastSeenAnnouncementVersion(userId),
  );

  const rememberAnnouncementVersion = useCallback((version: string) => {
    if (!version) return;
    setLastSeenAnnouncementVersion((previous) => {
      const stored = readLastSeenAnnouncementVersion(userId);
      const baseline = isNewerAnnouncementVersion(stored, previous) ? stored : previous;
      if (!isNewerAnnouncementVersion(version, baseline)) return baseline;
      try {
        window.localStorage.setItem(
          announcementLastSeenStorageKey(userId),
          version,
        );
      } catch {
        // Keep the read marker in memory when browser storage is unavailable.
      }
      return version;
    });
  }, [userId]);

  useEffect(() => {
    const storageKey = announcementLastSeenStorageKey(userId);
    setAnnouncementVersion("");
    setLastSeenAnnouncementVersion(readLastSeenAnnouncementVersion(userId));

    const handleStorage = (event: StorageEvent) => {
      if (event.key !== storageKey) return;
      const incoming = normalizeAnnouncementVersion(event.newValue);
      setLastSeenAnnouncementVersion((previous) => (
        isNewerAnnouncementVersion(incoming, previous) ? incoming : previous
      ));
    };
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, [userId]);

  useEffect(() => {
    if (
      announcementOpen
      && isNewerAnnouncementVersion(announcementVersion, lastSeenAnnouncementVersion)
    ) {
      rememberAnnouncementVersion(announcementVersion);
    }
  }, [
    announcementOpen,
    announcementVersion,
    lastSeenAnnouncementVersion,
    rememberAnnouncementVersion,
  ]);

  const hasUnreadAnnouncement = isNewerAnnouncementVersion(
    announcementVersion,
    lastSeenAnnouncementVersion,
  );

  const openAnnouncements = () => {
    rememberAnnouncementVersion(announcementVersion);
    setAnnouncementOpen(true);
    setAnnouncementRefreshKey((current) => current + 1);
  };

  const refreshAnnouncements = useCallback(() => setAnnouncementRefreshKey((current) => current + 1), []);
  return { announcementOpen, setAnnouncementOpen, announcementRefreshKey, setAnnouncementVersion, hasUnreadAnnouncement, openAnnouncements, refreshAnnouncements };
}
