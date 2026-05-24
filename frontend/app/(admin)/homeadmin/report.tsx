// app/(admin)/homeadmin/report.tsx
import React, { useEffect, useState, useCallback } from "react";
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  ActivityIndicator,
  Alert,
  Modal,
} from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";
import axiosInstance from "../../../src/config/axiosInstance";

export default function ReportScreen() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [summary, setSummary] = useState<{ items: any[]; total_reports: number }>({
    items: [],
    total_reports: 0,
  });
  const [processingIds, setProcessingIds] = useState<Record<string | number, boolean>>({});

  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [detailTarget, setDetailTarget] = useState<{ target_type: string; target_id: number } | null>(null);
  const [detailReports, setDetailReports] = useState<any[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);

  const authHeaders = useCallback(async () => {
    const token = await AsyncStorage.getItem("token");
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }, []);

  async function fetchSummary() {
    setLoading(true);
    try {
      const headers = await authHeaders();
      const res = await axiosInstance.get("/admin/reports/summary", { headers });
      setSummary(res.data || { items: [], total_reports: 0 });
    } catch (e: any) {
      console.warn("fetchSummary error", e);
      Alert.alert("ไม่สามารถโหลดข้อมูลรายงาน", String(e?.message || e));
      setSummary({ items: [], total_reports: 0 });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchSummary();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchSummary();
    setRefreshing(false);
  };

  async function markGuidesleepFeedDirty() {
    try {
      await AsyncStorage.setItem("refresh_guidesleep", "1");
    } catch (e) {
      // ignore
    }
  }

  async function deleteReportById(reportId: number) {
    setProcessingIds((p) => ({ ...p, [reportId]: true }));
    try {
      const headers = await authHeaders();
      try {
        const res = await axiosInstance.delete(`/admin/reports/${reportId}`, { headers });
        if (res.status !== 200 && res.status !== 204) {
          throw new Error(`Unexpected response status: ${res.status}`);
        }
      } catch (err: any) {
        const statusCode = err?.response?.status;
        if (statusCode === 405) {
          await axiosInstance.put(`/admin/reports/${reportId}`, { status: "rejected" }, { headers });
        } else {
          throw err;
        }
      }

      setDetailReports((prev) => prev.filter((r: any) => Number(r.id ?? r.report_id ?? 0) !== Number(reportId)));

      if (detailTarget) {
        setSummary((prev) => {
          const items = prev.items
            .map((it: any) => {
              if (it.target_type === detailTarget.target_type && Number(it.target_id) === Number(detailTarget.target_id)) {
                const newCount = Math.max(0, (it.report_count ?? 1) - 1);
                return { ...it, report_count: newCount };
              }
              return it;
            })
            .filter((it: any) => (it.report_count ?? 0) > 0);
          const total = Math.max(0, (prev.total_reports ?? 0) - 1);
          return { ...prev, items, total_reports: total };
        });
      } else {
        await fetchSummary();
      }

      Alert.alert("ปฏิเสธรายงานแล้ว", "ลบรายงานเรียบร้อย");
    } catch (e: any) {
      console.warn("deleteReportById error", e);
      const msg = e?.response?.data?.detail ?? e?.message ?? String(e);
      Alert.alert("ปฏิเสธไม่สำเร็จ", msg);
    } finally {
      setProcessingIds((p) => {
        const copy = { ...p };
        delete copy[reportId];
        return copy;
      });
    }
  }

  async function deleteAllReportsForTarget(target_type: string, target_id: number) {
    const confirmMsg = `ยืนยันการปฏิเสธทั้งหมดสำหรับ ${target_type} #${target_id}? การดำเนินการนี้จะลบรายงานทั้งหมดของโพสต์นี้`;
    Alert.alert("ยืนยัน", confirmMsg, [
      { text: "ยกเลิก", style: "cancel" },
      {
        text: "ตกลง",
        onPress: async () => {
          try {
            const headers = await authHeaders();

            const res = await axiosInstance.delete(
              `/admin/reports/target/${encodeURIComponent(target_type)}/${encodeURIComponent(String(target_id))}`,
              { headers }
            );

            const deleted = res?.data?.deleted ?? 0;

            if (deleted === 0) {
              Alert.alert("ไม่มีรายงาน", "โพสต์นี้ไม่มีรายงานให้ลบ");
              return;
            }

            setSummary((prev) => {
              const items = prev.items.filter(
                (it: any) => !(it.target_type === target_type && Number(it.target_id) === Number(target_id))
              );
              const total = Math.max(0, (prev.total_reports ?? 0) - deleted);
              return { ...prev, items, total_reports: total };
            });

            if (detailTarget && detailTarget.target_type === target_type && Number(detailTarget.target_id) === Number(target_id)) {
              setDetailReports([]);
            }

            Alert.alert("ปฏิเสธเรียบร้อย", `ลบรายงานทั้งหมด ${deleted} รายการของโพสต์นี้แล้ว`);
          } catch (e: any) {
            console.warn("deleteAllReportsForTarget error", e);
            const msg = e?.response?.data?.detail ?? e?.message ?? String(e);
            Alert.alert("ลบไม่สำเร็จ", msg);
          }
        },
      },
    ]);
  }

  async function updateReportStatus(reportId: number, status: "accepted" | "rejected") {
    setProcessingIds((p) => ({ ...p, [reportId]: true }));
    try {
      const headers = await authHeaders();
      await axiosInstance.put(`/admin/reports/${reportId}`, { status }, { headers });

      if (status === "accepted") {
        await markGuidesleepFeedDirty();
      }

      Alert.alert("อัปเดตเรียบร้อย", `รายงานถูกตั้งค่าเป็น: ${status}`);
      await fetchSummary();
      if (detailTarget) {
        await fetchReportsForTarget(detailTarget.target_type, detailTarget.target_id);
      }
    } catch (e: any) {
      console.warn("updateReportStatus error", e);
      Alert.alert("อัปเดตไม่สำเร็จ", String(e?.message || e));
    } finally {
      setProcessingIds((p) => {
        const copy = { ...p };
        delete copy[reportId];
        return copy;
      });
    }
  }

  function confirmUpdate(reportId: number, status: "accepted" | "rejected") {
    const msg =
      status === "accepted"
        ? "ยืนยันการยอมรับรายงาน? การยอมรับอาจซ่อนโพสต์ที่ถูกรายงาน"
        : "ยืนยันการปฏิเสธรายงาน? การปฏิเสธจะลบรายงานนี้ออก";
    Alert.alert("ยืนยัน", msg, [
      { text: "ยกเลิก", style: "cancel" },
      {
        text: "ตกลง",
        onPress: () => {
          if (status === "rejected") {
            deleteReportById(reportId);
          } else {
            updateReportStatus(reportId, status);
          }
        },
      },
    ]);
  }

  async function fetchReportsForTarget(target_type: string, target_id: number) {
    setDetailLoading(true);
    try {
      const headers = await authHeaders();
      const res = await axiosInstance.get("/admin/reports", {
        headers,
        params: { target_type, target_id },
      });

      const allReports = Array.isArray(res.data) ? res.data : [];
      const filtered = allReports.filter((r: any) => {
        const rt = r.target_type ?? r.targetType ?? r.type ?? null;
        const rid = r.target_id ?? r.targetId ?? r.target ?? null;
        return rt === target_type && Number(rid) === Number(target_id);
      });

      setDetailReports(filtered);
    } catch (e: any) {
      console.warn("fetchReportsForTarget error", e);
      Alert.alert("ไม่สามารถโหลดรายละเอียดรายงาน", String(e?.message || e));
      setDetailReports([]);
    } finally {
      setDetailLoading(false);
    }
  }

  function openDetailModal(target_type: string, target_id: number) {
    setDetailTarget({ target_type, target_id });
    setDetailModalVisible(true);
    fetchReportsForTarget(target_type, target_id);
  }

  async function acceptAllReportsForTarget(target_type: string, target_id: number) {
    const key = `accept-${target_type}-${target_id}`;
    const confirmMsg = `ยืนยันการยอมรับรายงานทั้งหมดและซ่อน ${target_type} #${target_id}?`;
    Alert.alert("ยืนยัน", confirmMsg, [
      { text: "ยกเลิก", style: "cancel" },
      {
        text: "ตกลง",
        onPress: async () => {
          setProcessingIds((p) => ({ ...p, [key]: true }));
          try {
            const headers = await authHeaders();
            const res = await axiosInstance.post(
              `/admin/reports/target/${encodeURIComponent(target_type)}/${encodeURIComponent(String(target_id))}/accept`,
              {},
              { headers }
            );

            const accepted = res?.data?.accepted_reports ?? 0;
            const hidden = res?.data?.hidden ?? false;

            if (hidden) {
              await markGuidesleepFeedDirty();
            }

            setSummary((prev) => {
              const items = prev.items.filter((it: any) => !(it.target_type === target_type && Number(it.target_id) === Number(target_id)));
              const total = Math.max(0, (prev.total_reports ?? 0) - accepted);
              return { ...prev, items, total_reports: total };
            });

            if (detailTarget && detailTarget.target_type === target_type && Number(detailTarget.target_id) === Number(target_id)) {
              setDetailReports([]);
            }

            Alert.alert("ยอมรับเรียบร้อย", `ยอมรับรายงาน ${accepted} รายการ${hidden ? " และซ่อนโพสต์แล้ว" : ""}`);
          } catch (e: any) {
            console.warn("acceptAllReportsForTarget error", e);
            const msg = e?.response?.data?.detail ?? e?.message ?? String(e);
            Alert.alert("ยอมรับไม่สำเร็จ", msg);
          } finally {
            setProcessingIds((p) => {
              const copy = { ...p };
              delete copy[key];
              return copy;
            });
          }
        },
      },
    ]);
  }

  function renderSummaryItem({ item }: { item: any }) {
    const groupKey = `accept-${item.target_type}-${item.target_id}`;
    const repId = item.report_id ?? item.id ?? null;

    return (
      <View style={styles.card}>
        <View style={styles.row}>
          <Text style={styles.title}>
            {item.target_type} #{item.target_id}
          </Text>

          <TouchableOpacity onPress={() => openDetailModal(item.target_type, item.target_id)} style={styles.countBtn}>
            <Text style={styles.count}>{item.report_count} รายงาน</Text>
          </TouchableOpacity>
        </View>

        <Text style={styles.owner}>
          เจ้าของโพสต์: {item.owner_name ?? "ไม่ระบุ"} {item.owner_id ? `(#${item.owner_id})` : ""}
        </Text>

        <Text style={styles.reasonsLabel}>ตัวอย่างเหตุผล:</Text>
        <Text style={styles.reasonsText}>{item.reasons_sample ?? "ไม่มีเหตุผลตัวอย่าง"}</Text>

        <View style={styles.actionsRow}>
          <TouchableOpacity
            style={[styles.actionButton, styles.viewButton]}
            onPress={() => {
              Alert.alert("ไปยังโพสต์", `เปิด ${item.target_type} id=${item.target_id}`);
            }}
          >
            <Text style={[styles.actionText, { color: "#333" }]}>ดูโพสต์</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.actionButton, styles.acceptButton]}
            onPress={() => {
              if (repId) {
                confirmUpdate(repId, "accepted");
              } else {
                acceptAllReportsForTarget(item.target_type, item.target_id);
              }
            }}
            disabled={!!processingIds[groupKey] || !!processingIds[repId ?? 0]}
          >
            {processingIds[groupKey] || processingIds[repId ?? 0] ? <ActivityIndicator color="#fff" /> : <Text style={styles.actionText}>ยอมรับ</Text>}
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.actionButton, styles.rejectButton]}
            onPress={() => deleteAllReportsForTarget(item.target_type, item.target_id)}
            disabled={!!processingIds[groupKey] || !!processingIds[repId ?? 0]}
          >
            <Text style={styles.actionText}>ปฏิเสธ</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  function renderDetailReport({ item }: { item: any }) {
    const rid = item.id ?? item.report_id ?? 0;
    return (
      <View style={styles.detailCard}>
        <View style={{ flexDirection: "row", justifyContent: "space-between" }}>
          <Text style={{ fontWeight: "700" }}>รายงาน #{rid}</Text>
          <Text style={{ color: "#666" }}>{item.created_at ? new Date(item.created_at).toLocaleString() : ""}</Text>
        </View>

        <Text style={{ marginTop: 6, color: "#333" }}>{item.reason ?? "ไม่มีเหตุผล"}</Text>
        <Text style={{ marginTop: 6, color: "#666" }}>
          ผู้รายงาน: {item.reporter_name ?? item.user_name ?? "ไม่ระบุ"} {item.user_id ? `(#${item.user_id})` : ""}
        </Text>

        <View style={{ flexDirection: "row", justifyContent: "flex-end", marginTop: 8 }}>
          <TouchableOpacity style={[styles.actionButton, styles.acceptButton]} onPress={() => confirmUpdate(rid, "accepted")} disabled={!!processingIds[rid]}>
            {processingIds[rid] ? <ActivityIndicator color="#fff" /> : <Text style={styles.actionText}>ยอมรับ</Text>}
          </TouchableOpacity>

          <TouchableOpacity style={[styles.actionButton, styles.rejectButton]} onPress={() => confirmUpdate(rid, "rejected")} disabled={!!processingIds[rid]}>
            <Text style={styles.actionText}>ปฏิเสธ</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.header}>รายงานโพสต์ (Admin)</Text>

      <View style={styles.summaryRow}>
        <Text style={styles.summaryText}>รวมรายงานทั้งหมด: </Text>
        <Text style={styles.summaryCount}>{summary.total_reports}</Text>
        <TouchableOpacity style={styles.refreshBtn} onPress={fetchSummary}>
          <Text style={styles.refreshText}>รีเฟรช</Text>
        </TouchableOpacity>
      </View>

      {loading ? (
        <View style={styles.loadingWrap}>
          <ActivityIndicator size="large" />
          <Text style={{ marginTop: 8 }}>กำลังโหลดข้อมูล...</Text>
        </View>
      ) : (
        <FlatList
          data={summary.items || []}
          keyExtractor={(it, idx) => `${it.target_type}-${it.target_id}-${idx}`}
          renderItem={renderSummaryItem}
          contentContainerStyle={summary.items && summary.items.length ? undefined : styles.emptyContainer}
          ListEmptyComponent={<Text style={styles.emptyText}>ยังไม่มีรายงาน</Text>}
          refreshing={refreshing}
          onRefresh={onRefresh}
          keyboardShouldPersistTaps="handled"
        />
      )}

      <Modal visible={detailModalVisible} animationType="slide" transparent={true} onRequestClose={() => setDetailModalVisible(false)}>
        <View style={styles.modalBackdrop}>
          <View style={[styles.modalContent, { maxHeight: "85%" }]}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
              <Text style={styles.modalTitle}>รายงานสำหรับ: {detailTarget ? `${detailTarget.target_type} #${detailTarget.target_id}` : ""}</Text>
              <TouchableOpacity onPress={() => setDetailModalVisible(false)}>
                <Text style={{ color: "#007AFF", fontWeight: "700" }}>ปิด</Text>
              </TouchableOpacity>
            </View>

            {detailLoading ? (
              <View style={{ padding: 20, alignItems: "center" }}>
                <ActivityIndicator />
                <Text style={{ marginTop: 8 }}>กำลังโหลดรายละเอียด...</Text>
              </View>
            ) : detailReports.length === 0 ? (
              <View style={{ padding: 16 }}>
                <Text style={{ color: "#666" }}>ยังไม่มีรายงานแยกสำหรับโพสต์นี้</Text>
              </View>
            ) : (
              <FlatList
                data={detailReports}
                keyExtractor={(r) => String(r.id ?? r.report_id ?? Math.random())}
                renderItem={renderDetailReport}
                contentContainerStyle={{ paddingVertical: 8 }}
                keyboardShouldPersistTaps="handled"
              />
            )}
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16, backgroundColor: "#fff" },
  header: { fontSize: 20, fontWeight: "700", marginBottom: 12 },
  summaryRow: { flexDirection: "row", alignItems: "center", marginBottom: 12 },
  summaryText: { fontSize: 16, color: "#333" },
  summaryCount: { fontSize: 16, fontWeight: "700", marginLeft: 6, color: "#d9534f" },
  refreshBtn: { marginLeft: 12, paddingHorizontal: 10, paddingVertical: 4, borderRadius: 6, backgroundColor: "#eee" },
  refreshText: { color: "#333" },

  loadingWrap: { flex: 1, justifyContent: "center", alignItems: "center" },
  emptyContainer: { flex: 1, justifyContent: "center", alignItems: "center", paddingTop: 40 },
  emptyText: { color: "#666" },

  card: { borderWidth: 1, borderColor: "#eee", borderRadius: 8, padding: 12, marginBottom: 12, backgroundColor: "#fafafa" },
  row: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 6 },
  title: { fontSize: 16, fontWeight: "700" },

  countBtn: { paddingHorizontal: 8, paddingVertical: 4, borderRadius: 6, backgroundColor: "#fff0f0" },
  count: { fontSize: 14, color: "#d9534f", fontWeight: "700" },

  owner: { color: "#444", marginBottom: 6 },
  reasonsLabel: { fontSize: 13, color: "#666", marginBottom: 4 },
  reasonsText: { color: "#333", marginBottom: 8 },

  actionsRow: { flexDirection: "row", justifyContent: "flex-end", gap: 8 },
  actionButton: { paddingHorizontal: 12, paddingVertical: 8, borderRadius: 6, marginLeft: 8, minWidth: 80, alignItems: "center" },
  viewButton: { backgroundColor: "#f0f0f0" },
  acceptButton: { backgroundColor: "#28a745" },
  rejectButton: { backgroundColor: "#d9534f" },
  actionText: { color: "#fff", fontWeight: "700" },

  modalBackdrop: { flex: 1, backgroundColor: "rgba(0,0,0,0.35)", justifyContent: "center", padding: 16 },
  modalContent: { backgroundColor: "#fff", borderRadius: 10, padding: 12 },
  modalTitle: { fontSize: 16, fontWeight: "700", marginBottom: 8 },

  detailCard: { borderWidth: 1, borderColor: "#eee", borderRadius: 8, padding: 12, marginBottom: 10, backgroundColor: "#fff" },
});
