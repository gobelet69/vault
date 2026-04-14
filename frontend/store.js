import { create } from "zustand";

function withLocalStorage(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

export const useVaultStore = create((set, get) => ({
  theme: withLocalStorage("vault-theme", "dark"),
  viewMode: withLocalStorage("vault-view-mode", "list"),
  sortBy: "name",
  sortDir: "asc",
  search: "",
  selectedKeys: [],
  editorTabs: [],
  activeTabKey: null,
  offlineQueue: withLocalStorage("vault-offline-queue", []),

  setTheme(theme) {
    localStorage.setItem("vault-theme", JSON.stringify(theme));
    set({ theme });
  },
  setViewMode(viewMode) {
    localStorage.setItem("vault-view-mode", JSON.stringify(viewMode));
    set({ viewMode });
  },
  setSort(sortBy, sortDir) {
    set({ sortBy, sortDir });
  },
  setSearch(search) {
    set({ search });
  },
  setSelectedKeys(selectedKeys) {
    set({ selectedKeys });
  },
  clearSelection() {
    set({ selectedKeys: [] });
  },
  setEditorTabs(editorTabsOrUpdater) {
    set((state) => ({
      editorTabs:
        typeof editorTabsOrUpdater === "function"
          ? editorTabsOrUpdater(state.editorTabs)
          : editorTabsOrUpdater,
    }));
  },
  setActiveTabKey(activeTabKey) {
    set({ activeTabKey });
  },
  enqueueOfflineSave(item) {
    const next = [...get().offlineQueue, item];
    localStorage.setItem("vault-offline-queue", JSON.stringify(next));
    set({ offlineQueue: next });
  },
  dequeueOfflineSave(id) {
    const next = get().offlineQueue.filter((item) => item.id !== id);
    localStorage.setItem("vault-offline-queue", JSON.stringify(next));
    set({ offlineQueue: next });
  },
  setOfflineQueue(offlineQueue) {
    localStorage.setItem("vault-offline-queue", JSON.stringify(offlineQueue));
    set({ offlineQueue });
  },
}));
