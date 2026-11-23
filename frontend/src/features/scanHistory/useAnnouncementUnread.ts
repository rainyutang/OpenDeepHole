import { useCallback, useEffect, useRef, useState } from "react";

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

function pickNewerAnnouncementVersion(first: string, second: string) {
  return isNewerAnnouncementVersion(first, second) ? first : second;
}

export interface PublishedVersionChangeOptions {
  allowAutoOpen?: boolean;
}

export function useAnnouncementUnread(userId: string) {
  const [announcementOpen, setAnnouncementOpen] = useState(false);
  const [announcementRefreshKey, setAnnouncementRefreshKey] = useState(0);
  const announcementOpenRef = useRef(announcementOpen);
  announcementOpenRef.current = announcementOpen;

  const announcementVersionRef = useRef("");
  const lastSeenRef = useRef(readLastSeenAnnouncementVersion(userId));
  const trackedUserIdRef = useRef(userId);
  const effectUserIdRef = useRef(userId);

  if (trackedUserIdRef.current !== userId) {
    trackedUserIdRef.current = userId;
    announcementVersionRef.current = "";
    lastSeenRef.current = readLastSeenAnnouncementVersion(userId);
  }

  const rememberAnnouncementVersion = useCallback((version: string) => {
    if (!version) return;
    const baseline = pickNewerAnnouncementVersion(
      readLastSeenAnnouncementVersion(userId),
      lastSeenRef.current,
    );
    if (!isNewerAnnouncementVersion(version, baseline)) {
      lastSeenRef.current = baseline;
      return;
    }
    lastSeenRef.current = version;
    try {
      window.localStorage.setItem(
        announcementLastSeenStorageKey(userId),
        version,
      );
    } catch {
      // Keep the read marker in memory when browser storage is unavailable.
    }
  }, [userId]);

  useEffect(() => {
    const storageKey = announcementLastSeenStorageKey(userId);
    if (effectUserIdRef.current !== userId) {
      effectUserIdRef.current = userId;
      setAnnouncementOpen(false);
    }
    lastSeenRef.current = readLastSeenAnnouncementVersion(userId);

    if (typeof window === "undefined") return;
    const handleStorage = (event: StorageEvent) => {
      if (event.key !== storageKey) return;
      const incoming = normalizeAnnouncementVersion(event.newValue);
      lastSeenRef.current = pickNewerAnnouncementVersion(incoming, lastSeenRef.current);
    };
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, [userId]);

  const handlePublishedVersionChange = useCallback((
    version: string,
    options?: PublishedVersionChangeOptions,
  ) => {
    announcementVersionRef.current = version;
    if (!version) return;

    const baseline = pickNewerAnnouncementVersion(
      readLastSeenAnnouncementVersion(userId),
      lastSeenRef.current,
    );
    lastSeenRef.current = baseline;

    if (!isNewerAnnouncementVersion(version, baseline)) {
      return;
    }
    if (options?.allowAutoOpen === false) {
      return;
    }

    rememberAnnouncementVersion(version);
    if (!announcementOpenRef.current) {
      setAnnouncementOpen(true);
    }
  }, [rememberAnnouncementVersion, userId]);

  const closeAnnouncements = useCallback(() => {
    setAnnouncementOpen(false);
  }, []);

  const toggleAnnouncements = useCallback(() => {
    if (announcementOpenRef.current) {
      setAnnouncementOpen(false);
      return;
    }
    rememberAnnouncementVersion(announcementVersionRef.current);
    setAnnouncementOpen(true);
    setAnnouncementRefreshKey((current) => current + 1);
  }, [rememberAnnouncementVersion]);

  const refreshAnnouncements = useCallback(() => {
    setAnnouncementRefreshKey((current) => current + 1);
  }, []);

  return {
    announcementOpen,
    closeAnnouncements,
    announcementRefreshKey,
    handlePublishedVersionChange,
    toggleAnnouncements,
    refreshAnnouncements,
  };
}
