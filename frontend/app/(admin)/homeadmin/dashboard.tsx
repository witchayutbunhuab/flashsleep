// app/(admin)/homeadmin/DashboardScreen.tsx
import React, { useEffect, useState, useCallback, useRef } from "react";
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  RefreshControl,
  FlatList,
  TouchableOpacity,
  ActivityIndicator,
  Modal,
  Pressable,
  Alert,
} from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";
import axiosInstance from "../../../src/config/axiosInstance";
import StatCard from "./components/StatCard";

type ReportSummaryItem = {
  target_type: string;
  target_id: number;
  owner_id?: number | null;
  owner_name?: string | null;
  report_count: number;
  reasons_sample?: string | null;
  sample_report_id?: number | null;
};

type UserRoleItem = {
  id: number;
  first_name?: string;
  last_name?: string;
  email?: string;
  role?: string | null;
};

export default function DashboardScreen({ navigation }: any) {
  const [loading, setLoading] = useState(true); // initial load
  const [refreshing, setRefreshing] = useState(false); // pull-to-refresh
  const isMountedRef = useRef(true);
  const isFetchingRef = useRef(false); // prevent overlapping fetches
  const abortControllersRef = useRef<AbortController[]>([]);

  const [usersCount, setUsersCount] = useState<number | null>(null);
  const [guidesCount, setGuidesCount] = useState<number | null>(null);
  const [openReportsCount, setOpenReportsCount] = useState<number>(0);
  const [recentReports, setRecentReports] = useState<ReportSummaryItem[]>([]);
  const [recentGuides, setRecentGuides] = useState<any[]>([]);

  // roles & users
  const [rolesCount, setRolesCount] = useState<Record<string, number>>({});
  const [usersWithRoles, setUsersWithRoles] = useState<UserRoleItem[]>([]);
  const [rolesLoading, setRolesLoading] = useState(false);

  // users list for dashboard (top N)
  const [usersList, setUsersList] = useState<UserRoleItem[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);

  // show more toggle
  const [showAllUsers, setShowAllUsers] = useState(false);

  // role change modal state
  const [roleModalVisible, setRoleModalVisible] = useState(false);
  const [roleModalUser, setRoleModalUser] = useState<UserRoleItem | null>(null);
  const [roleChangingLoading, setRoleChangingLoading] = useState(false);

  // delete user loading state
  const [deletingUserId, setDeletingUserId] = useState<number | null>(null);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      // mark unmounted and abort any inflight requests
      isMountedRef.current = false;
      abortControllersRef.current.forEach((c) => {
        try {
          c.abort();
        } catch {}
      });
      abortControllersRef.current = [];
    };
  }, []);

  const authHeaders = useCallback(async () => {
    const token = await AsyncStorage.getItem("token");
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }, []);

  // helper: create AbortController and register it
  const createAbortController = useCallback(() => {
    const c = new AbortController();
    abortControllersRef.current.push(c);
    return c;
  }, []);

  // fetch roles and sample users
  const fetchRolesAndUsers = useCallback(
    async (headers: Record<string, string>) => {
      setRolesLoading(true);
      const controller = createAbortController();
      try {
        // prefer admin endpoint
        const res = await axiosInstance.get("/admin/users/roles", {
          headers,
          signal: controller.signal as any,
        }).catch(() => null);

        if (res && res.data) {
          const data = res.data || {};
          const counts = data.counts ?? {};
          if (isMountedRef.current) setRolesCount(counts);
          if (Array.isArray(data.users) && isMountedRef.current) {
            const sample = data.users.slice(0, 20).map((u: any) => ({
              id: Number(u.id),
              first_name: u.first_name ?? u.firstName ?? u.first ?? "",
              last_name: u.last_name ?? u.lastName ?? u.last ?? "",
              email: u.email ?? "",
              role: u.role ?? "user",
            }));
            if (isMountedRef.current) setUsersWithRoles(sample);
          } else {
            if (isMountedRef.current) setUsersWithRoles([]);
          }
          return;
        }

        // fallback: fetch users and aggregate
        const resUsers = await axiosInstance.get("/admin/users?limit=200", {
          headers,
          signal: controller.signal as any,
        }).catch(async () => {
          return axiosInstance.get("/users?limit=200", { headers, signal: controller.signal as any });
        });

        const users = Array.isArray(resUsers?.data) ? resUsers.data : resUsers?.data?.users ?? [];
        const counts: Record<string, number> = {};
        const sample: UserRoleItem[] = [];

        (users || []).forEach((u: any) => {
          const role = (u.role ?? "user") as string;
          counts[role] = (counts[role] ?? 0) + 1;
          if (sample.length < 20) {
            sample.push({
              id: Number(u.id),
              first_name: u.first_name ?? u.firstName ?? u.first ?? "",
              last_name: u.last_name ?? u.lastName ?? u.last ?? "",
              email: u.email ?? "",
              role,
            });
          }
        });

        if (isMountedRef.current) {
          setRolesCount(counts);
          setUsersWithRoles(sample);
        }
      } catch (e: any) {
        if (!controller.signal.aborted) {
          console.warn("fetchRolesAndUsers error", e?.message ?? e);
          if (isMountedRef.current) {
            setRolesCount({});
            setUsersWithRoles([]);
          }
        }
      } finally {
        if (isMountedRef.current) setRolesLoading(false);
      }
    },
    [createAbortController]
  );

  // fetch users for dashboard (top N) — improved to extract total count reliably
  const fetchUsersForDashboard = useCallback(
    async (headers: Record<string, string>, limit = 20) => {
      setUsersLoading(true);
      const controller = createAbortController();
      try {
        const res = await axiosInstance
          .get(`/admin/users?limit=${limit}`, {
            headers,
            signal: controller.signal as any,
          })
          .catch(async () => {
            return axiosInstance.get(`/users?limit=${limit}`, { headers, signal: controller.signal as any });
          });

        // normalize list
        const data = Array.isArray(res?.data) ? res.data : res?.data?.users ?? [];
        const normalized: UserRoleItem[] = (data || []).slice(0, limit).map((u: any) => ({
          id: Number(u.id),
          first_name: u.first_name ?? u.firstName ?? u.first ?? "",
          last_name: u.last_name ?? u.lastName ?? u.last ?? "",
          email: u.email ?? "",
          role: u.role ?? u.role_name ?? "user",
        }));

        // Try to extract total count from headers or body
        let totalFromResponse: number | null = null;
        try {
          const headerCount = res?.headers?.["x-total-count"] ?? res?.headers?.["X-Total-Count"];
          if (headerCount !== undefined && headerCount !== null) {
            const parsed = Number(headerCount);
            if (!Number.isNaN(parsed)) totalFromResponse = parsed;
          }
        } catch {}

        if (totalFromResponse === null) {
          const bodyTotal = res?.data?.total ?? res?.data?.meta?.total ?? null;
          if (typeof bodyTotal === "number") totalFromResponse = bodyTotal;
          else if (typeof bodyTotal === "string") {
            const parsed = Number(bodyTotal);
            if (!Number.isNaN(parsed)) totalFromResponse = parsed;
          }
        }

        if (isMountedRef.current) {
          setUsersList(normalized);
          // If we found a reliable total, set it. Otherwise, do not overwrite an existing accurate usersCount.
          if (totalFromResponse !== null) {
            setUsersCount(totalFromResponse);
          } else if (usersCount === null) {
            // fallback: use normalized length only if we don't already have a total
            setUsersCount(normalized.length);
          }
        }
      } catch (e: any) {
        if (!controller.signal.aborted) {
          console.warn("fetchUsersForDashboard error", e?.message ?? e);
          if (isMountedRef.current) setUsersList([]);
        }
      } finally {
        if (isMountedRef.current) setUsersLoading(false);
      }
    },
    [createAbortController, usersCount]
  );

  // main overview fetch — guarded to avoid overlapping calls
  const fetchOverview = useCallback(
    async (opts?: { force?: boolean; isRefresh?: boolean }) => {
      // prevent overlapping fetches unless forced
      if (isFetchingRef.current && !opts?.force) return;
      isFetchingRef.current = true;

      // if this is a user-initiated refresh, use refreshing state; otherwise keep initial loading state
      if (opts?.isRefresh) {
        setRefreshing(true);
      } else {
        // only set loading true if it's the very first load
        if (!refreshing && !usersList.length && !recentGuides.length && !recentReports.length) {
          setLoading(true);
        }
      }

      const controller = createAbortController();
      try {
        const headers = await authHeaders();

        // users count (try admin count endpoint first)
        try {
          const resUsers = await axiosInstance
            .get("/admin/users/count", { headers, signal: controller.signal as any })
            .catch(() => null);
          if (resUsers && resUsers.data !== undefined) {
            const maybeCount = Number(resUsers.data?.count ?? resUsers.data ?? null);
            if (!Number.isNaN(maybeCount) && isMountedRef.current) {
              setUsersCount(maybeCount);
            }
          } else {
            // fallback: try to read paginated total from users endpoint or headers
            const res = await axiosInstance.get("/admin/users?limit=1", { headers, signal: controller.signal as any }).catch(() => null);
            if (res) {
              // header
              const headerCount = res?.headers?.["x-total-count"] ?? res?.headers?.["X-Total-Count"];
              if (headerCount !== undefined && headerCount !== null) {
                const parsed = Number(headerCount);
                if (!Number.isNaN(parsed) && isMountedRef.current) setUsersCount(parsed);
              } else if (res.data && typeof res.data === "object" && res.data.total !== undefined) {
                const parsed = Number(res.data.total);
                if (!Number.isNaN(parsed) && isMountedRef.current) setUsersCount(parsed);
              }
            }
          }
        } catch (e) {
          // ignore per-endpoint errors
        }

        // guides count
        try {
          const resGuides = await axiosInstance
            .get("/guidesleep/count", { headers, signal: controller.signal as any })
            .catch(() => null);
          if (resGuides && resGuides.data !== undefined) {
            if (isMountedRef.current) setGuidesCount(Number(resGuides.data?.count ?? resGuides.data ?? 0));
          } else {
            const res = await axiosInstance.get("/guidesleep?limit=1", { headers, signal: controller.signal as any }).catch(() => null);
            if (res && res.data && typeof res.data === "object" && res.data.total !== undefined) {
              if (isMountedRef.current) setGuidesCount(Number(res.data.total));
            }
          }
        } catch (e) {
          // ignore
        }

        // reports summary
        try {
          const res = await axiosInstance.get("/admin/reports/summary", { headers, signal: controller.signal as any }).catch(() => null);
          if (res && res.data) {
            const summary = res.data || { items: [], total_reports: 0 };
            if (isMountedRef.current) {
              setOpenReportsCount(Number(summary.total_reports ?? 0));
              setRecentReports((summary.items || []).slice(0, 5));
            }
          } else {
            if (isMountedRef.current) {
              setOpenReportsCount(0);
              setRecentReports([]);
            }
          }
        } catch (e) {
          // ignore
        }

        // recent guides
        try {
          const res = await axiosInstance.get("/guidesleep?limit=5&offset=0", { headers, signal: controller.signal as any }).catch(() => null);
          if (res && res.data) {
            const guides = Array.isArray(res.data)
              ? res.data.map((g: any) => {
                  const userName =
                    g.user_name ?? (g.user ? `${g.user.first_name ?? ""} ${g.user.last_name ?? ""}`.trim() : "");
                  const userRole = g.user?.role ?? g.role ?? "user";
                  return { ...g, user_name: userName, user_role: userRole };
                })
              : [];
            if (isMountedRef.current) setRecentGuides(guides.slice(0, 5));
          } else {
            if (isMountedRef.current) setRecentGuides([]);
          }
        } catch (e) {
          // ignore
        }

        // roles & sample users
        await fetchRolesAndUsers(headers);

        // users list for dashboard (top 20) — this will also attempt to set usersCount from headers/body
        await fetchUsersForDashboard(headers, 20);
      } catch (e: any) {
        if (!controller.signal.aborted) {
          console.warn("fetchOverview error", e?.message ?? e);
        }
      } finally {
        // clear controller from registry
        abortControllersRef.current = abortControllersRef.current.filter((c) => c !== controller);
        isFetchingRef.current = false;
        if (isMountedRef.current) {
          setRefreshing(false);
          setLoading(false);
        }
      }
    },
    [authHeaders, createAbortController, fetchRolesAndUsers, fetchUsersForDashboard, refreshing, usersList.length, recentGuides.length, recentReports.length]
  );

  useEffect(() => {
    // initial load
    fetchOverview({ force: true, isRefresh: false });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onRefresh = async () => {
    await fetchOverview({ force: true, isRefresh: true });
  };

  // Toggle handler: when user taps "ดูสมาชิกทั้งหมด", fetch larger list and expand.
  const handleToggleShowAll = useCallback(
    async (e?: any) => {
      // prevent overlapping toggles
      if (isFetchingRef.current) return;
      isFetchingRef.current = true;
      try {
        const headers = await authHeaders();
        const newShow = !showAllUsers;
        setShowAllUsers(newShow);

        // if expanding, fetch larger page (e.g., 200). If collapsing, fetch top 20.
        const limit = newShow ? 200 : 20;
        await fetchUsersForDashboard(headers, limit);
      } catch (err) {
        console.warn("handleToggleShowAll error", err);
      } finally {
        isFetchingRef.current = false;
      }
    },
    [authHeaders, fetchUsersForDashboard, showAllUsers]
  );

  // Open role modal for a user
  const openRoleModal = useCallback((user: UserRoleItem) => {
    setRoleModalUser(user);
    setRoleModalVisible(true);
  }, []);

  // API call to change role
  const changeUserRole = useCallback(
    async (userId: number, newRole: string) => {
      setRoleChangingLoading(true);
      const controller = createAbortController();
      try {
        const headers = await authHeaders();
        // Example endpoint: PATCH /admin/users/:id/role with body { role: "admin" }
        // Adjust endpoint/method according to your backend API.
        const res = await axiosInstance.patch(
          `/admin/users/${userId}/role`,
          { role: newRole },
          { headers, signal: controller.signal as any }
        ).catch(async (err) => {
          // If backend uses a different endpoint, try a generic update
          try {
            return await axiosInstance.put(`/admin/users/${userId}`, { role: newRole }, { headers, signal: controller.signal as any });
          } catch (e) {
            throw err;
          }
        });

        // If success, update local lists and role counts
        if (res && (res.status === 200 || res.status === 204 || res.status === 201)) {
          // Update usersList
          setUsersList((prev) =>
            prev.map((u) => (u.id === userId ? { ...u, role: newRole } : u))
          );
          // Update usersWithRoles sample
          setUsersWithRoles((prev) =>
            prev.map((u) => (u.id === userId ? { ...u, role: newRole } : u))
          );
          // Update rolesCount: decrement old role, increment new role
          setRolesCount((prev) => {
            const copy = { ...prev };
            // find previous role from lists (prefer roleModalUser)
            const prevRole = roleModalUser?.id === userId ? roleModalUser.role ?? "user" : (usersList.find(u => u.id === userId)?.role ?? "user");
            if (prevRole && typeof copy[prevRole] === "number") {
              copy[prevRole] = Math.max(0, copy[prevRole] - 1);
            }
            copy[newRole] = (copy[newRole] ?? 0) + 1;
            return copy;
          });

          // Close modal
          setRoleModalVisible(false);
          setRoleModalUser(null);
        } else {
          throw new Error("ไม่สามารถเปลี่ยนบทบาทได้");
        }
      } catch (e: any) {
        if (!controller.signal.aborted) {
          console.warn("changeUserRole error", e?.message ?? e);
          Alert.alert("เกิดข้อผิดพลาด", "ไม่สามารถเปลี่ยนบทบาทผู้ใช้ได้ ลองอีกครั้ง");
        }
      } finally {
        setRoleChangingLoading(false);
        // remove controller
        abortControllersRef.current = abortControllersRef.current.filter((c) => c !== controller);
      }
    },
    [authHeaders, createAbortController, roleModalUser, usersList]
  );

  // API call to delete user
  const deleteUser = useCallback(
    async (userId: number) => {
      // confirm
      Alert.alert(
        "ลบผู้ใช้",
        "คุณแน่ใจหรือไม่ว่าต้องการลบผู้ใช้นี้? การกระทำนี้ไม่สามารถย้อนกลับได้",
        [
          { text: "ยกเลิก", style: "cancel" },
          {
            text: "ลบ",
            style: "destructive",
            onPress: async () => {
              setDeletingUserId(userId);
              const controller = createAbortController();
              try {
                const headers = await authHeaders();
                // Expect backend to support DELETE /admin/users/:id
                const res = await axiosInstance.delete(`/admin/users/${userId}`, {
                  headers,
                  signal: controller.signal as any,
                }).catch((err) => {
                  // try fallback endpoint if any (e.g., soft-delete)
                  throw err;
                });

                if (res && (res.status === 200 || res.status === 204)) {
                  // remove from usersList and usersWithRoles
                  setUsersList((prev) => prev.filter((u) => u.id !== userId));
                  setUsersWithRoles((prev) => prev.filter((u) => u.id !== userId));
                  // decrement counts if possible
                  setRolesCount((prev) => {
                    const copy = { ...prev };
                    const removedRole = usersList.find((u) => u.id === userId)?.role ?? roleModalUser?.role ?? null;
                    if (removedRole && typeof copy[removedRole] === "number") {
                      copy[removedRole] = Math.max(0, copy[removedRole] - 1);
                    }
                    return copy;
                  });
                  // decrement usersCount if present
                  setUsersCount((prev) => (typeof prev === "number" ? Math.max(0, prev - 1) : prev));
                  // close modal if open for this user
                  if (roleModalUser?.id === userId) {
                    setRoleModalVisible(false);
                    setRoleModalUser(null);
                  }
                } else {
                  throw new Error("ลบผู้ใช้ไม่สำเร็จ");
                }
              } catch (e: any) {
                if (!controller.signal.aborted) {
                  console.warn("deleteUser error", e?.message ?? e);
                  Alert.alert("เกิดข้อผิดพลาด", "ไม่สามารถลบผู้ใช้ได้ ลองอีกครั้ง");
                }
              } finally {
                setDeletingUserId(null);
                abortControllersRef.current = abortControllersRef.current.filter((c) => c !== controller);
              }
            },
          },
        ],
        { cancelable: true }
      );
    },
    [authHeaders, createAbortController, roleModalUser, usersList]
  );

  const renderReportItem = ({ item }: { item: ReportSummaryItem }) => (
    <TouchableOpacity
      style={styles.listItem}
      onPress={() => navigation?.navigate?.("ReportDetail", { reportId: item.sample_report_id ?? null })}
    >
      <View style={{ flex: 1 }}>
        <Text style={styles.listTitle}>
          {item.target_type} #{item.target_id}
        </Text>
        <Text style={styles.listSubtitle}>
          เจ้าของ: {item.owner_name ?? "ไม่ระบุ"} • {item.report_count} รายงาน
        </Text>
        {item.reasons_sample ? (
          <Text style={styles.reasonsText} numberOfLines={2}>
            ตัวอย่างเหตุผล: {item.reasons_sample}
          </Text>
        ) : null}
      </View>
      <View style={styles.listAction}>
        <Text style={styles.badge}>{item.report_count}</Text>
      </View>
    </TouchableOpacity>
  );

  const renderGuideItem = ({ item }: { item: any }) => {
    const ownerFullName =
      item.user_name && item.user_name.trim() !== ""
        ? item.user_name
        : `${item.user?.first_name ?? ""} ${item.user?.last_name ?? ""}`.trim() || "ไม่ระบุ";
    const ownerRole = item.user_role ?? item.user?.role ?? "user";
    return (
      <TouchableOpacity style={styles.listItem} onPress={() => navigation?.navigate?.("GuideDetail", { id: item.id })}>
        <View style={{ flex: 1 }}>
          <Text style={styles.listTitle}>{item.title ?? `Guide #${item.id}`}</Text>
          <Text style={styles.listSubtitle}>
            โดย {ownerFullName} • {ownerRole}
          </Text>
        </View>
      </TouchableOpacity>
    );
  };

  const renderRolesBreakdown = () => {
    const entries = Object.entries(rolesCount).sort((a, b) => b[1] - a[1]);
    if (rolesLoading) return <ActivityIndicator size="small" />;
    if (entries.length === 0) return <Text style={styles.emptyText}>ไม่พบข้อมูลบทบาทสมาชิก</Text>;
    return (
      <View style={{ marginTop: 8 }}>
        <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
          {entries.map(([role, count]) => (
            <View key={role} style={styles.roleChip}>
              <Text style={styles.roleChipText}>
                {role} • {count}
              </Text>
            </View>
          ))}
        </View>

        <View style={{ marginTop: 12 }}>
          <Text style={{ fontWeight: "700", marginBottom: 6 }}>ตัวอย่างสมาชิก (สูงสุด 20)</Text>
          {usersWithRoles.length === 0 ? (
            <Text style={styles.emptyText}>ไม่มีตัวอย่างสมาชิก</Text>
          ) : (
            <FlatList
              data={usersWithRoles}
              keyExtractor={(u) => String(u.id)}
              renderItem={({ item }) => (
                <View style={styles.roleListItem}>
                  <Text style={{ fontWeight: "600" }}>
                    {item.first_name ?? ""} {item.last_name ?? ""}
                  </Text>
                  <Text style={{ color: "#666", fontSize: 12 }}>
                    {item.email ?? "—"} • {item.role ?? "user"}
                  </Text>
                </View>
              )}
              scrollEnabled={false}
            />
          )}
        </View>
      </View>
    );
  };

  // Render user row with delete button placed before the role badge
  const renderUserRow = ({ item }: { item: UserRoleItem }) => (
    <View style={styles.userRow}>
      <TouchableOpacity onPress={() => openRoleModal(item)} style={{ flex: 1 }}>
        <Text style={styles.name}>
          {(item.first_name ?? "").trim() || "(ไม่มีชื่อ)"} {(item.last_name ?? "").trim() || ""}
        </Text>
        <Text style={styles.meta}>{item.email ?? "—"}</Text>
      </TouchableOpacity>

      <View style={{ flexDirection: "row", alignItems: "center" }}>
        {/* Delete button placed before the role badge */}
        <TouchableOpacity
          onPress={() => deleteUser(item.id)}
          style={styles.deleteButton}
          disabled={deletingUserId !== null}
        >
          {deletingUserId === item.id ? (
            <ActivityIndicator size="small" color="#fff" />
          ) : (
            <Text style={styles.deleteButtonText}>ลบ</Text>
          )}
        </TouchableOpacity>

        <TouchableOpacity onPress={() => openRoleModal(item)} style={styles.roleBadgeWrap}>
          <Text style={styles.roleBadge}>{(item.role ?? "user").toString()}</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  // compute display count: prefer rolesCount['user'] if available, then usersCount, then usersList.length
  const displayUsersCount =
    typeof rolesCount["user"] === "number" ? rolesCount["user"] : usersCount !== null ? usersCount : usersList.length;

  return (
    <>
      <ScrollView contentContainerStyle={styles.container} refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
        <Text style={styles.header}>Admin Dashboard</Text>

        {loading ? (
          <View style={styles.loadingWrap}>
            <ActivityIndicator size="large" />
          </View>
        ) : (
          <>
            <View style={styles.statsRow}>
              <StatCard title="Users" value={displayUsersCount !== null ? String(displayUsersCount) : "—"} />
              <StatCard title="Guides" value={guidesCount !== null ? String(guidesCount) : "—"} />
              <StatCard title="Open Reports" value={String(openReportsCount)} />
            </View>

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>รายงานล่าสุด</Text>
              {recentReports.length === 0 ? (
                <Text style={styles.emptyText}>ยังไม่มีรายงาน</Text>
              ) : (
                <FlatList data={recentReports} keyExtractor={(it, idx) => `${it.target_type}-${it.target_id}-${idx}`} renderItem={renderReportItem} scrollEnabled={false} />
              )}
              
            </View>

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>ไกด์ล่าสุด</Text>
              {recentGuides.length === 0 ? (
                <Text style={styles.emptyText}>ยังไม่มีไกด์</Text>
              ) : (
                <FlatList data={recentGuides} keyExtractor={(it: any) => String(it.id)} renderItem={renderGuideItem} scrollEnabled={false} />
              )}
              
            </View>

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>สมาชิก (ตัวอย่าง)</Text>
              {usersLoading ? (
                <ActivityIndicator />
              ) : usersList.length === 0 ? (
                <Text style={styles.emptyText}>ยังไม่มีสมาชิกที่แสดง</Text>
              ) : (
                <FlatList data={usersList} keyExtractor={(u) => String(u.id)} renderItem={renderUserRow} scrollEnabled={false} />
              )}

              <TouchableOpacity
                style={[styles.linkButton, { marginTop: 8 }]}
                onPress={handleToggleShowAll}
              >
                <Text style={styles.linkText}>
                  {showAllUsers ? "ซ่อนสมาชิกเพิ่มเติม" : "ดูสมาชิกทั้งหมด"}
                </Text>
              </TouchableOpacity>
            </View>

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>สมาชิกตามบทบาท</Text>
              {renderRolesBreakdown()}
              
            </View>

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>กิจกรรมสรุป (7 วันล่าสุด)</Text>
              <View style={styles.simpleChart}>
                {[2, 5, 3, 6, 4, 7, 5].map((v, i) => (
                  <View key={i} style={styles.chartBarWrap}>
                    <View style={[styles.chartBar, { height: 10 + v * 8 }]} />
                    <Text style={styles.chartLabel}>Day {i + 1}</Text>
                  </View>
                ))}
              </View>
            </View>
          </>
        )}
      </ScrollView>

      {/* Role selection modal (delete option removed from modal; delete remains as button in list) */}
      <Modal
        visible={roleModalVisible}
        transparent
        animationType="fade"
        onRequestClose={() => {
          if (!roleChangingLoading && deletingUserId === null) {
            setRoleModalVisible(false);
            setRoleModalUser(null);
          }
        }}
      >
        <View style={modalStyles.backdrop}>
          <View style={modalStyles.modal}>
            <Text style={modalStyles.modalTitle}>จัดการผู้ใช้</Text>
            <Text style={modalStyles.modalSubtitle}>
              {(roleModalUser?.first_name ?? "(ไม่มีชื่อ)") + " " + (roleModalUser?.last_name ?? "")}
            </Text>

            <View style={{ marginTop: 12 }}>
              <Pressable
                style={({ pressed }) => [modalStyles.option, pressed && modalStyles.optionPressed]}
                onPress={() => {
                  if (!roleChangingLoading && roleModalUser) changeUserRole(roleModalUser.id, "user");
                }}
              >
                <Text style={modalStyles.optionText}>ตั้งเป็น user</Text>
                {roleChangingLoading && <ActivityIndicator size="small" style={{ marginLeft: 8 }} />}
              </Pressable>

              <Pressable
                style={({ pressed }) => [modalStyles.option, pressed && modalStyles.optionPressed]}
                onPress={() => {
                  if (!roleChangingLoading && roleModalUser) changeUserRole(roleModalUser.id, "admin");
                }}
              >
                <Text style={modalStyles.optionText}>ตั้งเป็น admin</Text>
                {roleChangingLoading && <ActivityIndicator size="small" style={{ marginLeft: 8 }} />}
              </Pressable>
            </View>

            <View style={{ marginTop: 14, flexDirection: "row", justifyContent: "flex-end" }}>
              <TouchableOpacity
                onPress={() => {
                  if (!roleChangingLoading && deletingUserId === null) {
                    setRoleModalVisible(false);
                    setRoleModalUser(null);
                  }
                }}
                style={{ paddingHorizontal: 12, paddingVertical: 8 }}
              >
                <Text style={{ color: "#007AFF", fontWeight: "700" }}>ปิด</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </>
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, backgroundColor: "#fff" },
  header: { fontSize: 20, fontWeight: "700", marginBottom: 12 },
  loadingWrap: { height: 200, justifyContent: "center", alignItems: "center" },

  statsRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 16,
  },

  section: {
    marginBottom: 18,
    paddingVertical: 8,
    borderTopWidth: 1,
    borderTopColor: "#f0f0f0",
  },
  sectionTitle: { fontSize: 16, fontWeight: "700", marginBottom: 8 },

  listItem: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: "#f2f2f2",
  },
  listTitle: { fontSize: 14, fontWeight: "700" },
  listSubtitle: { fontSize: 12, color: "#666", marginTop: 4 },
  reasonsText: { fontSize: 12, color: "#444", marginTop: 6 },

  listAction: { marginLeft: 12, alignItems: "center" },
  badge: {
    backgroundColor: "#d9534f",
    color: "#fff",
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 12,
    overflow: "hidden",
    fontWeight: "700",
  },

  linkButton: { marginTop: 8 },
  linkText: { color: "#007AFF", fontWeight: "700" },

  emptyText: { color: "#888", fontSize: 13 },

  simpleChart: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-end",
    paddingVertical: 12,
  },
  chartBarWrap: { alignItems: "center", width: 40 },
  chartBar: { width: 20, backgroundColor: "#007AFF", borderRadius: 4 },
  chartLabel: { fontSize: 10, color: "#666", marginTop: 6, textAlign: "center" },

  // roles UI
  roleChip: {
    backgroundColor: "#f0f8ff",
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 16,
    marginRight: 8,
    marginBottom: 8,
  },
  roleChipText: { color: "#007AFF", fontWeight: "700" },
  roleListItem: {
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: "#f2f2f2",
  },

  // users list
  userRow: { flexDirection: "row", paddingVertical: 12, alignItems: "center", justifyContent: "space-between" },
  name: { fontWeight: "700", fontSize: 14 },
  meta: { color: "#666", fontSize: 12, marginTop: 4 },
  roleBadgeWrap: { paddingLeft: 8 },
  roleBadge: {
    backgroundColor: "#f0f8ff",
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 8,
    color: "#007AFF",
    fontWeight: "700",
  },

  // delete button
  deleteButton: {
    backgroundColor: "#d9534f",
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
    marginRight: 8,
    minWidth: 44,
    alignItems: "center",
    justifyContent: "center",
  },
  deleteButtonText: { color: "#fff", fontWeight: "700" },
});

const modalStyles = StyleSheet.create({
  backdrop: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.4)",
    justifyContent: "center",
    alignItems: "center",
    padding: 20,
  },
  modal: {
    width: "100%",
    maxWidth: 420,
    backgroundColor: "#fff",
    borderRadius: 12,
    padding: 16,
    elevation: 6,
  },
  modalTitle: { fontSize: 16, fontWeight: "800" },
  modalSubtitle: { fontSize: 13, color: "#666", marginTop: 6 },
  option: {
    paddingVertical: 12,
    paddingHorizontal: 12,
    borderRadius: 8,
    backgroundColor: "#f7f7f7",
    marginBottom: 8,
    flexDirection: "row",
    alignItems: "center",
  },
  optionPressed: { opacity: 0.8 },
  optionText: { fontWeight: "700", color: "#007AFF" },
});
