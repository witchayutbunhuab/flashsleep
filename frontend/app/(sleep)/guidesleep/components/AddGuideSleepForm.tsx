// app/(sleep)/guidesleep/components/AddGuideSleepForm.tsx
import React, { useEffect, useRef, useState } from "react";
import {
  View,
  TextInput,
  TouchableOpacity,
  Text,
  StyleSheet,
  Alert,
  Platform,
  KeyboardAvoidingView,
  ScrollView,
  ActivityIndicator,
  NativeSyntheticEvent,
  TextInputFocusEventData,
} from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";
import axiosInstance from "../../../../src/config/axiosInstance"; // ปรับ path ให้ตรงโปรเจคของคุณ
import { postGuideSleep as svcPostGuideSleep } from "../services/api"; // ถ้ามี
import MaterialCommunityIcons from "react-native-vector-icons/MaterialCommunityIcons";
import DateTimePicker, { Event } from "@react-native-community/datetimepicker";

const sleepCategories = [
  { label: "แนะนำหลับเร็ว", icon: "weather-night" },
  { label: "ตื่นนอนให้สดชื่น", icon: "white-balance-sunny" },
  { label: "ท่านอนที่เหมาะสม", icon: "bed" },
  { label: "ตัวช่วยนอนหลับ", icon: "meditation" },
];

function formatDateISO(d: Date) {
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function formatDateDisplay(d: Date) {
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${dd}/${mm}/${yyyy}`;
}

function formatTimeDisplay(d: Date) {
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

function formatTimePayload(d: Date) {
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

/**
 * AddGuideSleepForm
 *
 * Changes in this version:
 * - The component renders a compact "เพิ่ม GuideSleep +" button when collapsed.
 * - When expanded, the form content is placed inside an internal ScrollView with a fixed maxHeight.
 *   This lets the parent screen (QuickScreen) keep its header ("โพสต์: ...") visible while the
 *   user scrolls the form content to reach the Cancel or Save buttons.
 * - KeyboardAvoidingView is used so inputs are not obscured on iOS.
 * - Date/time pickers are modal (no automatic scrolling when opening).
 *
 * Usage:
 * - Place this component inline in QuickScreen above the posts list.
 * - The header in QuickScreen remains visible; the form scrolls internally when expanded.
 */
export default function AddGuideSleepForm({ defaultCategory }: { defaultCategory?: string }) {
  const fallbackCategory = defaultCategory ?? sleepCategories[0].label;
  const [showForm, setShowForm] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string>(fallbackCategory);
  const [note, setNote] = useState("");
  const [startDateObj, setStartDateObj] = useState<Date | null>(null);
  const [endDateObj, setEndDateObj] = useState<Date | null>(null);
  const [sleepTimeObj, setSleepTimeObj] = useState<Date | null>(null);
  const [wakeTimeObj, setWakeTimeObj] = useState<Date | null>(null);

  const [token, setToken] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [showPicker, setShowPicker] = useState<{
    mode: "date" | "time" | null;
    field: "start" | "end" | "sleep" | "wake" | null;
    visible: boolean;
  }>({ mode: null, field: null, visible: false });

  const innerScrollRef = useRef<ScrollView | null>(null);
  const noteRef = useRef<TextInput | null>(null);

  useEffect(() => {
    const loadAuth = async () => {
      try {
        const storedToken = await AsyncStorage.getItem("token");
        const storedUserId = await AsyncStorage.getItem("user_id");
        let uid = storedUserId ?? null;
        if (!uid) {
          const rawUser = (await AsyncStorage.getItem("user")) || (await AsyncStorage.getItem("profile"));
          if (rawUser) {
            try {
              const parsed = JSON.parse(rawUser);
              if (parsed && (parsed.id || parsed.user_id)) {
                uid = String(parsed.id ?? parsed.user_id);
              }
            } catch {
              uid = rawUser;
            }
          }
        }
        if (storedToken) setToken(storedToken);
        if (uid) setUserId(uid);
      } catch (e) {
        console.warn("loadAuth error", e);
      }
    };
    loadAuth();
  }, []);

  async function callPostGuideSleep(authToken: string | null, payload: any) {
    if (typeof svcPostGuideSleep === "function") {
      return svcPostGuideSleep(authToken, payload);
    }
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (authToken) headers.Authorization = `Bearer ${authToken}`;
    return axiosInstance.post("/guidesleep", payload, { headers });
  }

  const validatePayload = () => {
    const tNote = (note || "").trim();
    if (!tNote) {
      Alert.alert("กรุณากรอกข้อความโพสต์");
      return false;
    }
    if (!startDateObj || !endDateObj) {
      Alert.alert("กรุณาเลือกวันที่เริ่มและวันที่สิ้นสุด");
      return false;
    }
    if (!sleepTimeObj || !wakeTimeObj) {
      Alert.alert("กรุณาเลือกเวลานอนและเวลาตื่น");
      return false;
    }
    if (endDateObj.getTime() < startDateObj.getTime()) {
      Alert.alert("วันที่ไม่ถูกต้อง", "วันสิ้นสุดต้องไม่ก่อนวันเริ่ม");
      return false;
    }
    return true;
  };

  const handleSubmit = async () => {
    if (!token || !userId) {
      Alert.alert("ไม่พบ token หรือ user_id", "กรุณาเข้าสู่ระบบก่อนใช้งาน");
      return;
    }

    if (!validatePayload()) return;

    setIsSubmitting(true);
    try {
      const payload = {
        category: selectedCategory,
        note: note.trim(),
        start_date: formatDateISO(startDateObj!),
        end_date: formatDateISO(endDateObj!),
        sleep_time: formatTimePayload(sleepTimeObj!),
        wake_time: formatTimePayload(wakeTimeObj!),
        user_id: userId,
      };

      const res = await callPostGuideSleep(token, payload);

      if (res && (res.status === 200 || res.status === 201 || res.status === 204 || res.data)) {
        try {
          await AsyncStorage.setItem("refresh_guidesleep", "1");
        } catch {}
        Alert.alert("บันทึกสำเร็จ");
        // reset form
        setNote("");
        setStartDateObj(null);
        setEndDateObj(null);
        setSleepTimeObj(null);
        setWakeTimeObj(null);
        setSelectedCategory(fallbackCategory);
        setShowForm(false);
      } else {
        const msg = res?.data?.detail ?? "ไม่สามารถบันทึกได้";
        Alert.alert("เกิดข้อผิดพลาด", String(msg));
      }
    } catch (error: any) {
      console.error("โพสต์ล้มเหลว:", error);
      const serverMsg = error?.response?.data?.detail ?? error?.response?.data ?? error?.message ?? String(error);
      Alert.alert("เกิดข้อผิดพลาด", String(serverMsg));
    } finally {
      setIsSubmitting(false);
    }
  };

  // Picker handlers (modal pickers)
  const openDatePicker = (field: "start" | "end") => {
    setShowPicker({ mode: "date", field, visible: true });
  };
  const openTimePicker = (field: "sleep" | "wake") => {
    setShowPicker({ mode: "time", field, visible: true });
  };

  const onPickerChange = (event: Event, selected?: Date | undefined) => {
    if (!showPicker.visible) return;
    const { field } = showPicker;
    setShowPicker({ mode: null, field: null, visible: false });

    if ((event as any)?.type === "dismissed") {
      return;
    }

    const value = selected ?? undefined;
    if (!value) return;

    if (field === "start") setStartDateObj(value);
    else if (field === "end") setEndDateObj(value);
    else if (field === "sleep") setSleepTimeObj(value);
    else if (field === "wake") setWakeTimeObj(value);
  };

  // When focusing the note input, scroll the internal ScrollView so Save/Cancel are reachable
  const handleFocus = (_e: NativeSyntheticEvent<TextInputFocusEventData>) => {
    setTimeout(() => {
      try {
        innerScrollRef.current?.scrollToEnd({ animated: true });
      } catch {}
    }, 120);
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : undefined}
      keyboardVerticalOffset={Platform.OS === "ios" ? 88 : 60}
      style={styles.kav}
    >
      <View style={styles.wrapper}>
        {!showForm ? (
          <TouchableOpacity style={styles.button} onPress={() => setShowForm(true)}>
            <Text style={styles.buttonText}>เพิ่ม GuideSleep +</Text>
          </TouchableOpacity>
        ) : (
          // The form area has a fixed maxHeight and its own ScrollView so the parent header stays visible.
          <View style={styles.formContainer}>
            <ScrollView
              ref={innerScrollRef}
              contentContainerStyle={styles.formScrollContent}
              keyboardShouldPersistTaps="handled"
              showsVerticalScrollIndicator={true}
            >
              <Text style={styles.label}>เลือกประเภทโพสต์:</Text>
              <View style={styles.radioRow}>
                {sleepCategories.map(({ label, icon }) => (
                  <TouchableOpacity key={label} style={styles.radioItem} onPress={() => setSelectedCategory(label)}>
                    <View style={styles.radioCircle}>{selectedCategory === label && <View style={styles.radioDot} />}</View>
                    <MaterialCommunityIcons name={icon} size={16} color="#007AFF" style={{ marginRight: 4 }} />
                    <Text style={styles.radioLabel}>{label}</Text>
                  </TouchableOpacity>
                ))}
              </View>

              <TextInput
                ref={noteRef}
                style={[styles.input, { minHeight: 100 }]}
                placeholder="เพิ่มโพสการนอน..."
                value={note}
                onChangeText={setNote}
                multiline
                onFocus={handleFocus}
              />

              <Text style={styles.smallLabel}>วันเริ่มบันทึก</Text>
              <TouchableOpacity style={styles.pickerButton} onPress={() => openDatePicker("start")}>
                <Text style={styles.pickerText}>{startDateObj ? formatDateDisplay(startDateObj) : "เลือกวันเริ่ม (YYYY-MM-DD)"}</Text>
              </TouchableOpacity>

              <Text style={styles.smallLabel}>วันสิ้นสุดไกด์</Text>
              <TouchableOpacity style={styles.pickerButton} onPress={() => openDatePicker("end")}>
                <Text style={styles.pickerText}>{endDateObj ? formatDateDisplay(endDateObj) : "เลือกวันสิ้นสุด (YYYY-MM-DD)"}</Text>
              </TouchableOpacity>

              <Text style={styles.smallLabel}>เวลานอน</Text>
              <TouchableOpacity style={styles.pickerButton} onPress={() => openTimePicker("sleep")}>
                <Text style={styles.pickerText}>{sleepTimeObj ? formatTimeDisplay(sleepTimeObj) : "เลือกเวลา (HH:MM)"}</Text>
              </TouchableOpacity>

              <Text style={styles.smallLabel}>เวลาตื่น</Text>
              <TouchableOpacity style={styles.pickerButton} onPress={() => openTimePicker("wake")}>
                <Text style={styles.pickerText}>{wakeTimeObj ? formatTimeDisplay(wakeTimeObj) : "เลือกเวลา (HH:MM)"}</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={[styles.submitButton, isSubmitting && { opacity: 0.7 }]}
                onPress={handleSubmit}
                disabled={isSubmitting}
              >
                {isSubmitting ? <ActivityIndicator color="#fff" /> : <Text style={styles.submitText}>บันทึก GuideSleep</Text>}
              </TouchableOpacity>

              <TouchableOpacity style={styles.cancelButton} onPress={() => setShowForm(false)}>
                <Text style={styles.cancelText}>ยกเลิก</Text>
              </TouchableOpacity>

              {/* small spacer so last button isn't flush to the bottom */}
              <View style={{ height: 12 }} />
            </ScrollView>
          </View>
        )}

        {/* DateTimePicker modal */}
        {showPicker.visible && showPicker.mode && (
          <DateTimePicker
            value={
              (showPicker.field === "start" && startDateObj) ||
              (showPicker.field === "end" && endDateObj) ||
              (showPicker.field === "sleep" && sleepTimeObj) ||
              (showPicker.field === "wake" && wakeTimeObj) ||
              new Date()
            }
            mode={showPicker.mode}
            display={Platform.OS === "ios" ? "spinner" : "default"}
            onChange={onPickerChange}
            is24Hour={true}
          />
        )}
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  kav: { width: "100%" },
  wrapper: { paddingHorizontal: 20, paddingTop: 8, backgroundColor: "#fff" },

  // Collapsed button
  button: {
    backgroundColor: "#007AFF",
    paddingVertical: 10,
    paddingHorizontal: 20,
    borderRadius: 8,
    alignSelf: "flex-start",
  },
  buttonText: { color: "#fff", fontSize: 16, fontWeight: "600" },

  // Form container: fixed maxHeight so parent header remains visible
  formContainer: {
    marginTop: 10,
    maxHeight: 360, // adjust as needed; ensures internal scrolling
    borderWidth: 1,
    borderColor: "#eee",
    borderRadius: 10,
    overflow: "hidden",
    backgroundColor: "#fff",
  },
  formScrollContent: {
    padding: 12,
  },

  label: { fontSize: 16, fontWeight: "500", marginBottom: 8 },
  smallLabel: { fontSize: 13, color: "#444", marginTop: 8, marginBottom: 6 },

  radioRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    marginBottom: 12,
  },
  radioItem: {
    flexDirection: "row",
    alignItems: "center",
    marginRight: 16,
    marginBottom: 8,
  },
  radioCircle: {
    height: 20,
    width: 20,
    borderRadius: 10,
    borderWidth: 2,
    borderColor: "#007AFF",
    alignItems: "center",
    justifyContent: "center",
    marginRight: 6,
  },
  radioDot: {
    height: 10,
    width: 10,
    borderRadius: 5,
    backgroundColor: "#007AFF",
  },
  radioLabel: {
    fontSize: 14,
    color: "#333",
  },

  input: {
    borderWidth: 1,
    borderColor: "#ccc",
    padding: 10,
    borderRadius: 8,
    marginBottom: 10,
    backgroundColor: "#fff",
    textAlignVertical: "top",
  },

  pickerButton: {
    borderWidth: 1,
    borderColor: "#ccc",
    paddingVertical: 12,
    paddingHorizontal: 10,
    borderRadius: 8,
    marginBottom: 8,
    backgroundColor: "#fff",
  },
  pickerText: {
    color: "#222",
  },

  submitButton: {
    backgroundColor: "#007AFF",
    padding: 12,
    borderRadius: 8,
    alignItems: "center",
    marginTop: 10,
  },
  submitText: { color: "#fff", fontSize: 16 },

  cancelButton: {
    marginTop: 12,
    alignItems: "center",
    paddingVertical: 8,
  },
  cancelText: {
    color: "#007AFF",
    fontSize: 14,
    textDecorationLine: "underline",
  },
});
