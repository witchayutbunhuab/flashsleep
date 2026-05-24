// app/(admin)/homeadmin/api/admin.ts
import AsyncStorage from "@react-native-async-storage/async-storage";

const BACKEND = "http://192.168.1.2:8000";

/**
 * Build auth headers. Always include Content-Type for JSON requests.
 * If no token is present, Authorization header will be an empty string.
 */
async function authHeaders(): Promise<Record<string, string>> {
  const token = await AsyncStorage.getItem("token");
  return {
    Authorization: token ? `Bearer ${token}` : "",
    "Content-Type": "application/json",
  };
}

/**
 * Create a new admin quest.
 * payload should be a plain object; this function stringifies it before sending.
 */
export async function createAdminQuest(payload: any) {
  const headers = await authHeaders();
  const res = await fetch(`${BACKEND}/admin/quests`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Failed to create quest: ${res.status} ${text}`);
  }
  // try to parse JSON, but handle empty body gracefully
  try {
    return await res.json();
  } catch {
    return {};
  }
}

/**
 * Fetch all admin quests.
 */
export async function fetchAdminQuests() {
  const headers = await authHeaders();
  const res = await fetch(`${BACKEND}/admin/quests`, {
    method: "GET",
    headers,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Failed to fetch quests: ${res.status} ${text}`);
  }
  try {
    return await res.json();
  } catch {
    return [];
  }
}

/**
 * Update a quest by id.
 * payload should be a plain object containing fields to update.
 */
export async function updateAdminQuest(questId: number, payload: any) {
  const headers = await authHeaders();
  const res = await fetch(`${BACKEND}/admin/quests/${questId}`, {
    method: "PUT",
    headers,
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Failed to update quest ${questId}: ${res.status} ${text}`);
  }
  try {
    return await res.json();
  } catch {
    return {};
  }
}

/**
 * Delete a quest by id.
 */
export async function deleteAdminQuest(questId: number) {
  const headers = await authHeaders();
  const res = await fetch(`${BACKEND}/admin/quests/${questId}`, {
    method: "DELETE",
    headers,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Failed to delete quest ${questId}: ${res.status} ${text}`);
  }
  // backend may return empty body on delete
  return { success: true };
}

/**
 * Default export for consumers that import the module as a default.
 * Keeps compatibility if some imports use default import instead of named.
 */
export default {
  createAdminQuest,
  fetchAdminQuests,
  updateAdminQuest,
  deleteAdminQuest,
};
