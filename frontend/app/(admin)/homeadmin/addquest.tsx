// app/(admin)/homeadmin/addquest.tsx
import React, { useEffect, useState, useRef } from "react";
import {
  View,
  Text,
  TextInput,
  Button,
  Alert,
  TouchableOpacity,
  FlatList,
  StyleSheet,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
} from "react-native";
import { useRouter } from "expo-router";
import {
  createAdminQuest,
  fetchAdminQuests,
  updateAdminQuest,
  deleteAdminQuest,
} from "./api/admin";

type AgeGroupKey = "child" | "teen" | "adult" | "senior";
type PeriodKey = "morning" | "afternoon" | "evening";

const AGE_GROUPS: { key: AgeGroupKey; label: string; range: string }[] = [
  { key: "child", label: "เด็ก", range: "0-12 ปี" },
  { key: "teen", label: "วัยรุ่น", range: "13-19 ปี" },
  { key: "adult", label: "ผู้ใหญ่", range: "20-59 ปี" },
  { key: "senior", label: "คนชรา", range: "60+ ปี" },
];

type AdminQuest = {
  id: number;
  title: string;
  description?: string | null;
  created_by?: number | null;
  status?: string;
  start_date?: string | null;
  end_date?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  parsedDesc?: QuestDescription | null;
};

type TaskItem = {
  text: string;
  score?: number;
};

type QuestDescription = {
  age_group?: string;
  periods: {
    morning: TaskItem[];
    afternoon: TaskItem[];
    evening: TaskItem[];
  };
};

export default function AddQuestScreen() {
  const router = useRouter();

  const [title, setTitle] = useState("");
  const [ageGroup, setAgeGroup] = useState<AgeGroupKey>("child");
  const [selectedPeriod, setSelectedPeriod] = useState<PeriodKey>("morning");
  const [submitting, setSubmitting] = useState(false);

  const [quests, setQuests] = useState<AdminQuest[]>([]);
  const [loadingQuests, setLoadingQuests] = useState(false);
  const [savingQuestIds, setSavingQuestIds] = useState<number[]>([]);
  const [deletingQuestIds, setDeletingQuestIds] = useState<number[]>([]);

  // ref to FlatList so we can scroll to top after creating
  const flatListRef = useRef<FlatList<any> | null>(null);
  // flag to indicate we just created a quest and want to scroll to top after reload
  const [justCreated, setJustCreated] = useState(false);

  useEffect(() => {
    loadQuests();
  }, []);

  const parseDescription = (desc?: string | null): QuestDescription | null => {
    if (!desc) return null;
    try {
      if (typeof desc === "string") {
        const parsed = JSON.parse(desc);
        return ensureTaskStructure(parsed);
      }
      return ensureTaskStructure(desc as any);
    } catch {
      return null;
    }
  };

  const ensureTaskStructure = (descObj: any): QuestDescription => {
    const out: QuestDescription = {
      age_group: descObj?.age_group || "child",
      periods: { morning: [], afternoon: [], evening: [] },
    };
    const periods = descObj?.periods || {};
    for (const p of ["morning", "afternoon", "evening"]) {
      const arr = periods[p] || [];
      out.periods[p as keyof QuestDescription["periods"]] = arr.map((it: any) => {
        if (typeof it === "string") {
          return { text: it, score: 10 };
        }
        return {
          text: it?.text || "",
          score: 10,
        };
      });
    }
    return out;
  };

  const loadQuests = async () => {
    setLoadingQuests(true);
    try {
      const rows = await fetchAdminQuests();
      const normalized: AdminQuest[] = (rows || []).map((r: any) => {
        const parsed = parseDescription(r.description);
        return {
          id: Number(r.id),
          title: r.title || "",
          description:
            typeof r.description === "string"
              ? r.description
              : JSON.stringify(r.description || parsed || {}),
          created_by: r.created_by ?? null,
          status: r.status ?? "draft",
          start_date: r.start_date ?? null,
          end_date: r.end_date ?? null,
          created_at: r.created_at ?? null,
          updated_at: r.updated_at ?? null,
          parsedDesc: parsed,
        };
      });
      setQuests(normalized);

      // if we just created a quest, scroll to top so user sees it
      if (justCreated) {
        // small delay to ensure FlatList rendered
        setTimeout(() => {
          try {
            flatListRef.current?.scrollToOffset({ offset: 0, animated: true });
          } catch {}
          setJustCreated(false);
        }, 120);
      }
    } catch (e) {
      console.warn("fetchAdminQuests error", e);
      Alert.alert("ไม่สามารถโหลดเควสได้");
    } finally {
      setLoadingQuests(false);
    }
  };

  const validate = () => {
    if (!title.trim()) {
      Alert.alert("กรุณากรอกชื่อเควส");
      return false;
    }
    if (!selectedPeriod) {
      Alert.alert("กรุณาเลือกช่วงวัน (เช้า/บ่าย/ค่ำ)");
      return false;
    }
    return true;
  };

  const submit = async () => {
    if (!validate()) return;
    setSubmitting(true);
    try {
      const singleTask: TaskItem = { text: title.trim(), score: 10 };
      const descObj: QuestDescription = {
        age_group: ageGroup,
        periods: {
          morning: selectedPeriod === "morning" ? [singleTask] : [],
          afternoon: selectedPeriod === "afternoon" ? [singleTask] : [],
          evening: selectedPeriod === "evening" ? [singleTask] : [],
        },
      };
      const payload = {
        title: title.trim(),
        description: JSON.stringify(descObj),
        status: "published",
      };

      // create quest on backend
      await createAdminQuest(payload);

      // show success, clear form but stay on same screen
      Alert.alert("สร้างสำเร็จ");
      setTitle("");
      setSelectedPeriod("morning");

      // mark that we just created so loadQuests will scroll to top
      setJustCreated(true);
      await loadQuests();

      // NOTE: intentionally do NOT call router.back() — we stay on the same page
    } catch (e) {
      console.warn("createAdminQuest error", e);
      Alert.alert("สร้างไม่สำเร็จ");
    } finally {
      setSubmitting(false);
    }
  };

  const saveQuest = async (quest: AdminQuest) => {
    if (!quest.id) return;
    setSavingQuestIds((s) => [...s, quest.id!]);
    try {
      const payload: any = {};
      if (quest.description) payload.description = quest.description;
      await updateAdminQuest(quest.id, payload);
      Alert.alert("บันทึกสำเร็จ");
      await loadQuests();
    } catch (e) {
      console.warn("updateAdminQuest error", e);
      Alert.alert("บันทึกไม่สำเร็จ");
    } finally {
      setSavingQuestIds((s) => s.filter((id) => id !== quest.id));
    }
  };

  const onDeleteQuest = async (questId?: number) => {
    if (!questId) return;
    Alert.alert("ยืนยัน", "ต้องการลบเควสนี้หรือไม่?", [
      { text: "ยกเลิก", style: "cancel" },
      {
        text: "ลบ",
        style: "destructive",
        onPress: async () => {
          setDeletingQuestIds((s) => [...s, questId]);
          try {
            await deleteAdminQuest(questId);
            await loadQuests();
            Alert.alert("ลบสำเร็จ");
          } catch (e) {
            console.warn("deleteAdminQuest error", e);
            Alert.alert("ลบไม่สำเร็จ");
          } finally {
            setDeletingQuestIds((s) => s.filter((id) => id !== questId));
          }
        },
      },
    ]);
  };

  const renderQuestItem = ({ item }: { item: AdminQuest }) => {
    const descObj = item.parsedDesc || parseDescription(item.description) || ensureTaskStructure({});
    const periodOrder: PeriodKey[] = ["morning", "afternoon", "evening"];
    const firstNonEmpty = periodOrder.find((p) => (descObj.periods[p] || []).length > 0);
    const periodsToShow: PeriodKey[] = firstNonEmpty ? [firstNonEmpty] : [];
    const taskCount = periodsToShow.reduce((acc, p) => acc + (descObj.periods[p]?.length || 0), 0);
    const totalScore = taskCount * 20;

    return (
      <View style={styles.questBox}>
        <View style={styles.questHeader}>
          <Text style={styles.questTitle}>{item.title}</Text>
          <View style={{ flexDirection: "row" }}>
            <TouchableOpacity
              onPress={() => saveQuest(item)}
              style={[styles.smallBtn, styles.saveBtn]}
              disabled={savingQuestIds.includes(item.id)}
            >
              
            </TouchableOpacity>
            <TouchableOpacity
              onPress={() => onDeleteQuest(item.id)}
              style={[styles.smallBtn, styles.deleteBtn]}
              disabled={deletingQuestIds.includes(item.id)}
            >
              {deletingQuestIds.includes(item.id) ? (
                <ActivityIndicator color="#fff" />
              ) : (
                <Text style={styles.smallBtnText}>ลบ</Text>
              )}
            </TouchableOpacity>
          </View>
        </View>

        <Text style={styles.questMeta}>กลุ่มอายุ: {descObj.age_group}</Text>

        {periodsToShow.length === 0 && <Text style={{ color: "#666" }}>ไม่มีรายการ</Text>}

        {periodsToShow.map((periodKey) => {
          const label =
            periodKey === "morning" ? "ช่วงเช้า" : periodKey === "afternoon" ? "ช่วงบ่าย" : "ช่วงค่ำ";
          const arr: TaskItem[] = descObj.periods[periodKey] || [];
          return (
            <View key={`${item.id}-${periodKey}`} style={styles.questPeriod}>
              <Text style={styles.periodLabel}>{label}</Text>
              {arr.map((t, idx) => (
                <View key={`${item.id}-${periodKey}-${idx}`} style={styles.taskRow}>
                  <Text style={styles.taskText}>{t.text}</Text>
                  <View style={styles.scoreWrap}>
                    <Text style={styles.scoreText}>คะแนน: 20</Text>
                  </View>
                </View>
              ))}
            </View>
          );
        })}

        <View style={styles.questTotals}>
          <Text style={styles.totalText}>รวมคะแนน: {totalScore}</Text>
        </View>
      </View>
    );
  };

// ลบ const ListHeader ของเก่าทิ้งทั้งหมด แล้วใช้ return นี้แทนครับ

  return (
    <View style={styles.container}>
      <FlatList
        ref={(r) => (flatListRef.current = r)}
        data={quests}
        keyExtractor={(q) => String(q.id)}
        renderItem={renderQuestItem}
        ItemSeparatorComponent={() => <View style={{ height: 12 }} />}
        ListEmptyComponent={!loadingQuests ? <View style={styles.emptyContainer}><Text style={styles.emptyText}>ยังไม่มีเควส</Text></View> : null}
        contentContainerStyle={{ paddingBottom: 40 }}
        refreshing={loadingQuests}
        onRefresh={loadQuests}
        keyboardShouldPersistTaps="handled"
        ListHeaderComponent={
          <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : undefined} style={styles.headerWrapper}>
            <View style={styles.form}>
              <Text style={styles.heading}>สร้างภารกิจรายวัน (Admin)</Text>

              <Text style={styles.label}>ชื่อภารกิจ</Text>
              <TextInput
                value={title}
                onChangeText={setTitle}
                placeholder="เช่น ภารกิจรายวันสำหรับเด็ก"
                style={styles.input}
              />

              <Text style={[styles.label, { marginTop: 12 }]}>ชวงอายุ</Text>
              <View style={styles.ageRow}>
                {AGE_GROUPS.map((g) => {
                  const active = g.key === ageGroup;
                  return (
                    <TouchableOpacity
                      key={g.key}
                      onPress={() => setAgeGroup(g.key)}
                      style={[styles.ageBtn, active && styles.ageBtnActive]}
                    >
                      <Text style={[styles.ageBtnText, active && styles.ageBtnTextActive]}>
                        {g.label}
                      </Text>
                      <Text style={styles.ageRange}>{g.range}</Text>
                    </TouchableOpacity>
                  );
                })}
              </View>

              <Text style={[styles.label, { marginTop: 12 }]}>ช่วงวัน (เลือกได้ 1 ช่วง)</Text>
              <View style={styles.ageRow}>
                <TouchableOpacity
                  onPress={() => setSelectedPeriod("morning")}
                  style={[styles.periodBtn, selectedPeriod === "morning" && styles.periodBtnActive]}
                >
                  <Text style={[styles.periodBtnText, selectedPeriod === "morning" && styles.periodBtnTextActive]}>
                    เช้า
                  </Text>
                </TouchableOpacity>

                <TouchableOpacity
                  onPress={() => setSelectedPeriod("afternoon")}
                  style={[styles.periodBtn, selectedPeriod === "afternoon" && styles.periodBtnActive]}
                >
                  <Text style={[styles.periodBtnText, selectedPeriod === "afternoon" && styles.periodBtnTextActive]}>
                    บ่าย
                  </Text>
                </TouchableOpacity>

                <TouchableOpacity
                  onPress={() => setSelectedPeriod("evening")}
                  style={[styles.periodBtn, selectedPeriod === "evening" && styles.periodBtnActive]}
                >
                  <Text style={[styles.periodBtnText, selectedPeriod === "evening" && styles.periodBtnTextActive]}>
                    ค่ำ
                  </Text>
                </TouchableOpacity>
              </View>

              <View style={{ height: 16 }} />
              <Button title={submitting ? "กำลังสร้าง..." : "สร้างเควส"} onPress={submit} disabled={submitting} />
            </View>

            <View style={{ height: 20 }} />
            <View style={{ paddingHorizontal: 16 }}>
              <Text style={[styles.heading, { marginBottom: 12 }]}>รายการเควสที่มี (Admin)</Text>
              {loadingQuests && <ActivityIndicator />}
            </View>
          </KeyboardAvoidingView>
        }
      />
    </View>
  );

  return (
    <FlatList
      ref={(r) => (flatListRef.current = r)}
      data={quests}
      keyExtractor={(q) => String(q.id)}
      renderItem={renderQuestItem}
      ItemSeparatorComponent={() => <View style={{ height: 12 }} />}
      ListHeaderComponent={<ListHeader />}
      ListEmptyComponent={!loadingQuests ? <View style={styles.emptyContainer}><Text style={styles.emptyText}>ยังไม่มีเควส</Text></View> : null}
      contentContainerStyle={{ paddingBottom: 40 }}
      refreshing={loadingQuests}
      onRefresh={loadQuests}
      keyboardShouldPersistTaps="handled"
    />
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f7f7f7" },
  headerWrapper: { backgroundColor: "#f7f7f7" },
  form: { padding: 16, backgroundColor: "#fff", margin: 12, borderRadius: 8 },
  heading: { fontSize: 18, fontWeight: "800", marginBottom: 12 },
  label: { fontSize: 13, fontWeight: "700", marginBottom: 6 },
  input: {
    borderWidth: 1,
    borderColor: "#ddd",
    padding: 10,
    borderRadius: 8,
    backgroundColor: "#fff",
  },
  ageRow: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  ageBtn: {
    padding: 10,
    borderRadius: 8,
    backgroundColor: "#fff",
    borderWidth: 1,
    borderColor: "#eee",
    marginRight: 8,
    marginBottom: 8,
    minWidth: 90,
  },
  ageBtnActive: {
    backgroundColor: "#007aff",
    borderColor: "#007aff",
  },
  ageBtnText: { fontWeight: "700", color: "#333" },
  ageBtnTextActive: { color: "#fff" },
  ageRange: { fontSize: 11, color: "#666", marginTop: 4 },

  periodBtn: {
    padding: 10,
    borderRadius: 8,
    backgroundColor: "#fff",
    borderWidth: 1,
    borderColor: "#eee",
    marginRight: 8,
    marginBottom: 8,
    minWidth: 70,
    alignItems: "center",
  },
  periodBtnActive: {
    backgroundColor: "#007aff",
    borderColor: "#007aff",
  },
  periodBtnText: { fontWeight: "700", color: "#333" },
  periodBtnTextActive: { color: "#fff" },

  emptyContainer: { flex: 1, justifyContent: "center", alignItems: "center", paddingTop: 40 },
  emptyText: { color: "#666" },

  questBox: {
    backgroundColor: "#fff",
    padding: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#eee",
    marginHorizontal: 16,
  },
  questHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  questTitle: { fontWeight: "800", fontSize: 16, flex: 1 },
  questMeta: { color: "#666", marginTop: 6, marginBottom: 8 },
  questPeriod: { marginTop: 8 },
  periodLabel: { fontWeight: "800", marginBottom: 6 },
  taskRow: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 8 },
  taskText: { flex: 1, color: "#222" },
  scoreWrap: { marginLeft: 12, minWidth: 80, alignItems: "flex-end" },
  scoreText: { fontWeight: "700", color: "#333" },

  questTotals: { marginTop: 8, flexDirection: "row", justifyContent: "flex-end" },
  totalText: { fontWeight: "700" },

  smallBtn: {
    paddingHorizontal: 10,
    paddingVertical: 8,
    borderRadius: 6,
    marginLeft: 8,
  },
  
  deleteBtn: { backgroundColor: "#ff4d4f" },
  smallBtnText: { color: "#fff", fontWeight: "700" },
});
