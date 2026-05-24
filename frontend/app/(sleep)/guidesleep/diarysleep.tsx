// app/(sleep)/guidesleep/diarysleep.tsx
import AsyncStorage from "@react-native-async-storage/async-storage";
import DateTimePicker from "@react-native-community/datetimepicker";
import axios from "axios";
import { Audio } from "expo-av";
import Constants from "expo-constants";
import React, { useEffect, useRef, useState } from "react";
import {
    ActivityIndicator,
    Alert,
    FlatList,
    KeyboardAvoidingView,
    Linking,
    Modal,
    PermissionsAndroid,
    Platform,
    StyleSheet,
    Switch,
    Text,
    TextInput,
    TouchableOpacity,
    View,
} from "react-native";

const isExpoGo = Constants?.appOwnership === "expo";
const BACKEND_URL = "http://192.168.1.2:8000";
const MIC_ASKED_KEY = "mic_permission_asked";
const SOUND_ASKED_KEY = "sound_permission_asked";
const LAST_DIARY_ID_KEY = "last_created_diary_id";
const SCHEDULED_NOTIFS_KEY = "scheduled_local_notifications_v1";
const ANDROID_NOTIFICATION_CHANNEL_ID = "sleep-alerts-channel";

type DiaryItem = {
  id: number;
  note: string | null;
  start_date: string | null;
  end_date: string | null;
  sleep_time: string | null;
  wake_time: string | null;
  actual_sleep_start?: string | null;
  actual_wake_time?: string | null;
  total_sleep_minutes?: number | null;
  user_id?: number | null;
  user_name?: string | null;
  image_url?: string | null;
};

type ScheduledNotif = {
  id: string;
  title: string;
  dateIso: string;
};

function formatTime(d: Date) {
  return `${d.getHours().toString().padStart(2, "0")}:${d
    .getMinutes()
    .toString()
    .padStart(2, "0")}`;
}
function formatDate(d: Date) {
  return `${d.getFullYear()}-${(d.getMonth() + 1).toString().padStart(2, "0")}-${d
    .getDate()
    .toString()
    .padStart(2, "0")}`;
}

export default function DiarySleepScreen() {
  // URL สำรองสำหรับไฟล์เสียงแจ้งเตือน (ใช้เมื่อไม่มีไฟล์ท้องถิ่น)
  const ALARM_SOUND_URI =
    "https://actions.google.com/sounds/v1/alarms/alarm_clock.ogg";

  // ฟังก์ชันเล่นเสียงแจ้งเตือนแบบปลอดภัย (รองรับ URI)
  const playAlarmSound = async () => {
    try {
      const soundObj = new Audio.Sound();
      await soundObj.loadAsync({ uri: ALARM_SOUND_URI }, { shouldPlay: true });
      soundObj.setOnPlaybackStatusUpdate((status: any) => {
        try {
          if (status && status.didJustFinish) {
            soundObj.unloadAsync().catch(() => {});
          }
        } catch {}
      });
    } catch (e) {
      console.warn("playAlarmSound error", e);
    }
  };
  const initialDateObj = new Date();
  const [sleepTime, setSleepTime] = useState<Date>(new Date());
  const [wakeTime, setWakeTime] = useState<Date>(
    new Date(Date.now() + 8 * 60 * 60 * 1000),
  );
  const [date, setDate] = useState<Date>(initialDateObj);
  const [displayDate, setDisplayDate] = useState<string>(() =>
    formatDate(initialDateObj),
  );
  const [note, setNote] = useState<string>("");
  const [showSleepPicker, setShowSleepPicker] = useState(false);
  const [showWakePicker, setShowWakePicker] = useState(false);
  const [showDatePicker, setShowDatePicker] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [userId, setUserId] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [timeEnabled, setTimeEnabled] = useState(true);

  // Age-based sleep recommendation states
  const [age, setAge] = useState<number | null>(null);
  const [sleepHours, setSleepHours] = useState<string>("");
  const [loadingAge, setLoadingAge] = useState(true);

  const [sleepStartTs, setSleepStartTs] = useState<number | null>(null);
  const [pendingNotification, setPendingNotification] = useState<any | null>(
    null,
  );
  const responseListener = useRef<any>(null);
  const receivedListener = useRef<any>(null);

  const [showSoundModal, setShowSoundModal] = useState(false);

  const [entries, setEntries] = useState<DiaryItem[]>([]);
  const [loadingEntries, setLoadingEntries] = useState(false);
  const [entriesError, setEntriesError] = useState<string | null>(null);
  // calculated statistics
  const [avgSleepMinutes, setAvgSleepMinutes] = useState<number | null>(null);
  const [sleepQuality, setSleepQuality] = useState<string | null>(null);

  const [editModalVisible, setEditModalVisible] = useState(false);
  const [editingEntry, setEditingEntry] = useState<DiaryItem | null>(null);
  const [editingNote, setEditingNote] = useState("");
  const [savingEdit, setSavingEdit] = useState(false);

  const timersRef = useRef<Record<string, number>>({});
  const [scheduledList, setScheduledList] = useState<ScheduledNotif[]>([]);

  useEffect(() => {
    (async () => {
      try {
        const t = await AsyncStorage.getItem("token");
        const uid = await AsyncStorage.getItem("user_id");
        if (t) setToken(t);
        if (uid) {
          const n = Number(uid);
          setUserId(Number.isFinite(n) ? n : null);
        }
      } catch (e) {
        console.error("init storage read error", e);
      }
    })();

    (async () => {
      try {
        const alreadyAsked = await AsyncStorage.getItem(MIC_ASKED_KEY);
        if (!alreadyAsked) {
          await AsyncStorage.setItem(MIC_ASKED_KEY, "1");
          try {
            const { status } = await Audio.requestPermissionsAsync();
            if (status !== "granted") {
              Alert.alert(
                "ขอสิทธิ์ไมโครโฟน",
                "แอปต้องการสิทธิ์ไมโครโฟนเพื่อฟีเจอร์เสียง หากต้องการอนุญาตให้ไปที่การตั้งค่า",
                [
                  { text: "ยกเลิก", style: "cancel" },
                  {
                    text: "ไปที่ตั้งค่า",
                    onPress: () => Linking.openSettings(),
                  },
                ],
              );
            }
          } catch (e) {
            console.warn("Audio.requestPermissionsAsync failed", e);
          }

          if (Platform.OS === "android") {
            try {
              const has = await PermissionsAndroid.check(
                PermissionsAndroid.PERMISSIONS.RECORD_AUDIO,
              );
              if (!has) {
                const granted = await PermissionsAndroid.request(
                  PermissionsAndroid.PERMISSIONS.RECORD_AUDIO,
                );
                if (granted !== PermissionsAndroid.RESULTS.GRANTED) {
                  Alert.alert(
                    "สิทธิ์การบันทึกเสียงถูกปฏิเสธ",
                    "หากต้องการใช้ฟีเจอร์บันทึกเสียง โปรดอนุญาตสิทธิ์ไมโครโฟนในการตั้งค่า",
                    [
                      { text: "ยกเลิก", style: "cancel" },
                      {
                        text: "ไปที่ตั้งค่า",
                        onPress: () => Linking.openSettings(),
                      },
                    ],
                  );
                }
              }
            } catch (e) {
              console.warn("PermissionsAndroid RECORD_AUDIO request failed", e);
            }
          }
        }
      } catch (err) {
        console.error("mic permission flow error", err);
      }
    })();

    (async () => {
      try {
        const alreadyAskedSound = await AsyncStorage.getItem(SOUND_ASKED_KEY);
        if (!alreadyAskedSound) {
          setShowSoundModal(true);
        }
      } catch (e) {
        console.error("sound prompt flow error", e);
      }
    })();

    (async () => {
      try {
        const raw = await AsyncStorage.getItem(SCHEDULED_NOTIFS_KEY);
        const arr: ScheduledNotif[] = raw ? JSON.parse(raw) : [];
        setScheduledList(arr || []);
        arr?.forEach((s) => {
          const dt = new Date(s.dateIso);
          if (dt.getTime() > Date.now()) {
            scheduleForegroundTimer(s.id, s.title, dt);
          } else {
            removeScheduledById(s.id).catch(() => {});
          }
        });
      } catch (e) {
        console.warn("load scheduled notifs failed", e);
      }
    })();

    (async () => {
      if (isExpoGo) return;
      try {
        const Notifications = await import("expo-notifications");
        try {
          Notifications.setNotificationHandler({
            handleNotification: async () => ({
              shouldShowBanner: true,
              shouldShowList: true,
              shouldPlaySound: true,
              shouldSetBadge: false,
            }),
          });
        } catch (e) {
          console.warn("setNotificationHandler skipped", e);
        }

        try {
          responseListener.current =
            Notifications.addNotificationResponseReceivedListener(
              (response: any) => {
                const title =
                  response?.notification?.request?.content?.title ||
                  "การแจ้งเตือน";
                const body =
                  response?.notification?.request?.content?.body || "";
                setPendingNotification({
                  id: response?.notification?.request?.identifier,
                  title,
                  body,
                  data: response?.notification?.request?.content?.data,
                });
              },
            );
        } catch (e) {
          console.warn("addNotificationResponseReceivedListener failed", e);
          responseListener.current = null;
        }

        try {
          receivedListener.current =
            Notifications.addNotificationReceivedListener(
              (notification: any) => {
                const title =
                  notification?.request?.content?.title || "การแจ้งเตือน";
                const body = notification?.request?.content?.body || "";
                setPendingNotification({
                  id: notification?.request?.identifier,
                  title,
                  body,
                  data: notification?.request?.content?.data,
                });
              },
            );
        } catch (e) {
          console.warn("addNotificationReceivedListener failed", e);
          receivedListener.current = null;
        }
      } catch (err) {
        console.warn(
          "Notification listeners skipped (dynamic import failed)",
          err,
        );
      }
    })();

    return () => {
      Object.values(timersRef.current).forEach((id) => {
        try {
          clearTimeout(id);
        } catch {}
      });
      timersRef.current = {};

      (async () => {
        try {
          if (!isExpoGo) {
            const Notifications = await import("expo-notifications");
            try {
              if (
                responseListener.current &&
                typeof responseListener.current.remove === "function"
              ) {
                responseListener.current.remove();
              } else if (responseListener.current) {
                Notifications.removeNotificationSubscription(
                  responseListener.current as any,
                );
              }
            } catch (e) {}
            try {
              if (
                receivedListener.current &&
                typeof receivedListener.current.remove === "function"
              ) {
                receivedListener.current.remove();
              } else if (receivedListener.current) {
                Notifications.removeNotificationSubscription(
                  receivedListener.current as any,
                );
              }
            } catch (e) {}
          }
        } catch (e) {}
        responseListener.current = null;
        receivedListener.current = null;
      })();
    };
  }, []);

  useEffect(() => {
    if (token) {
      fetchEntries();
      fetchUserProfile();
    }
  }, [token]);

  const saveScheduledList = async (list: ScheduledNotif[]) => {
    try {
      await AsyncStorage.setItem(SCHEDULED_NOTIFS_KEY, JSON.stringify(list));
      setScheduledList(list);
    } catch (e) {
      console.warn("saveScheduledList failed", e);
    }
  };

  const addScheduled = async (s: ScheduledNotif) => {
    const next = [...scheduledList.filter((x) => x.id !== s.id), s];
    await saveScheduledList(next);
  };

  const removeScheduledById = async (id: string) => {
    try {
      const next = (scheduledList || []).filter((s) => s.id !== id);
      await saveScheduledList(next);
      const t = timersRef.current[id];
      if (t) {
        try {
          clearTimeout(t);
        } catch {}
        delete timersRef.current[id];
      }
    } catch (e) {
      console.warn("removeScheduledById failed", e);
    }
  };

  const createAndroidNotificationChannel = async () => {
    if (Platform.OS !== "android" || isExpoGo) return;

    try {
      const Notifications = await import("expo-notifications");
      if (
        Notifications &&
        typeof Notifications.setNotificationChannelAsync === "function"
      ) {
        const importance =
          Notifications.AndroidImportance?.MAX ??
          Notifications.AndroidImportance?.HIGH ??
          5;
        await Notifications.setNotificationChannelAsync(
          ANDROID_NOTIFICATION_CHANNEL_ID,
          {
            name: "Sleep Alerts",
            importance,
            sound: "default",
            vibrationPattern: [0, 250, 250, 250],
          },
        );
      }
    } catch (e) {
      console.warn("createAndroidNotificationChannel failed", e);
    }
  };

  const scheduleForegroundTimer = (
    id: string,
    title: string,
    dateObj: Date,
  ) => {
    const ms = dateObj.getTime() - Date.now();
    if (ms <= 0) return;
    if (timersRef.current[id]) {
      try {
        clearTimeout(timersRef.current[id]);
      } catch {}
    }
    const timerId = setTimeout(async () => {
      setPendingNotification({
        id,
        title,
        body: `ถึงเวลา ${title} แล้ว`,
        data: {},
      });
      // เล่นเสียงแจ้งเตือนทันทีเมื่อถึงเวลา (foreground)
      await playAlarmSound();
      await removeScheduledById(id).catch(() => {});
    }, ms) as unknown as number;
    timersRef.current[id] = timerId;
  };

  const safeIsoDate = (v: any): string | null => {
    if (!v) return null;
    try {
      if (typeof v === "string") {
        return v.length >= 10 ? v.slice(0, 10) : v;
      }
      if (v instanceof Date) return v.toISOString().slice(0, 10);
      return String(v).slice(0, 10);
    } catch {
      return null;
    }
  };

  const safeHHMM = (v: any): string | null => {
    if (!v) return null;
    if (typeof v === "string") {
      const m = v.match(/^(\d{2}):(\d{2})/);
      if (m) return `${m[1]}:${m[2]}`;
      const m2 = v.match(/^(\d{1,2})[:\.](\d{1,2})/);
      if (m2) return `${m2[1].padStart(2, "0")}:${m2[2].padStart(2, "0")}`;
      return v;
    }
    try {
      const d = new Date(v);
      if (isNaN(d.getTime())) return null;
      return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`;
    } catch {
      return null;
    }
  };

  const computeStats = (list: DiaryItem[]) => {
    if (!list || list.length === 0) {
      setAvgSleepMinutes(null);
      setSleepQuality(null);
      return;
    }
    const sum = list.reduce(
      (acc, it) => acc + (it.total_sleep_minutes ?? 0),
      0,
    );
    const avg = sum / list.length;
    setAvgSleepMinutes(avg);
    // simple quality rating based on average vs 480 minutes (8h)
    if (avg >= 480) {
      setSleepQuality("ดี");
    } else if (avg >= 360) {
      setSleepQuality("ปานกลาง");
    } else {
      setSleepQuality("แย่");
    }
  };

  // ฟังก์ชันคำนวณอายุจากวันเกิดแบบแม่นยำ (หักลบเดือนและวันที่ยังไม่ถึง)
  const calculateAge = (birthdateString: string) => {
    const birthDate = new Date(birthdateString);
    const today = new Date();
    let currentAge = today.getFullYear() - birthDate.getFullYear();
    const m = today.getMonth() - birthDate.getMonth();

    // ถ้าเดือนปัจจุบันยังไม่ถึงเดือนเกิด หรือเดือนเดียวกันแต่วันยังไม่ถึง ให้ลบอายุออก 1 ปี
    if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
      currentAge--;
    }
    return currentAge;
  };

  // โครงสร้างเกณฑ์การนอนตามอายุอ้างอิงจากคำแนะนำของผู้เชี่ยวชาญ
  const getSleepRecommendation = (currentAge: number) => {
    if (currentAge < 1)
      return { min: 14, max: 17, label: "ทารกแรกเกิด (0-11 เดือน)" };
    if (currentAge >= 1 && currentAge <= 2)
      return { min: 12, max: 15, label: "ทารก (1-2 ปี)" };
    if (currentAge >= 3 && currentAge <= 5)
      return { min: 11, max: 14, label: "เด็กวัยหัดเดิน (3-5 ปี)" };
    if (currentAge >= 6 && currentAge <= 9)
      return { min: 10, max: 13, label: "เด็กก่อนวัยเรียน (6-9 ปี)" };
    if (currentAge >= 10 && currentAge <= 13)
      return { min: 9, max: 11, label: "เด็กวัยเรียน (10-13 ปี)" };
    if (currentAge >= 14 && currentAge <= 17)
      return { min: 8, max: 10, label: "วัยรุ่น (14-17 ปี)" };
    if (currentAge >= 18 && currentAge <= 25)
      return { min: 7, max: 9, label: "วัยหนุ่มสาว (18-25 ปี)" };
    if (currentAge >= 26 && currentAge <= 64)
      return { min: 7, max: 9, label: "ผู้ใหญ่ (26-64 ปี)" };
    if (currentAge >= 65)
      return { min: 7, max: 8, label: "ผู้สูงอายุ (65 ปีขึ้นไป)" };
    return { min: 7, max: 9, label: "ผู้ใหญ่ (ค่าเริ่มต้น)" };
  };

  // ฟังก์ชันประเมินการนอน
  const evaluateSleep = () => {
    const recommended = age !== null ? getSleepRecommendation(age) : null;
    const hours = parseFloat(sleepHours);
    if (isNaN(hours) || !recommended) return null;

    if (hours >= recommended.min && hours <= recommended.max) {
      return { text: "ดี (อยู่ในเกณฑ์เหมาะสม)", color: "#28a745" };
    } else {
      return { text: "แย่ (ควรปรับเวลาการนอน)", color: "#d9534f" };
    }
  };

  // ฟังก์ชันประเมินการนอนจากข้อมูลแต่ละรายการ (ใช้ total_sleep_minutes)
  const evaluateSleepForRecord = (totalMinutes: number | null | undefined) => {
    if (!totalMinutes || totalMinutes <= 0) return null;
    const recommended =
      age !== null ? getSleepRecommendation(age) : getSleepRecommendation(20);
    const hours = totalMinutes / 60;

    if (hours >= recommended.min && hours <= recommended.max) {
      return {
        text: "ดี (อยู่ในเกณฑ์เหมาะสม)",
        color: "#28a745",
        bgColor: "#e8f5e9",
      };
    } else if (hours < recommended.min) {
      return {
        text: `แย่ (ควรนอน ${recommended.min}-${recommended.max} ชม.)`,
        color: "#d9534f",
        bgColor: "#fdeeea",
      };
    } else {
      return {
        text: `แย่ (ควรนอน ${recommended.min}-${recommended.max} ชม.)`,
        color: "#f0ad4e",
        bgColor: "#fcf4e3",
      };
    }
  };

  const fetchUserProfile = async () => {
    try {
      const token = await AsyncStorage.getItem("token");
      const userId = await AsyncStorage.getItem("user_id");

      if (!token || !userId) {
        setLoadingAge(false);
        return;
      }

      // เรียก GET /users/{user_id} ที่ถูกต้อง
      const response = await axios.get(`${BACKEND_URL}/users/${userId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      // ใช้ age จาก backend โดยตรง
      if (response.data.age !== undefined && response.data.age !== null) {
        setAge(response.data.age);
      } else if (response.data.birthdate) {
        // fallback: ถ้า backend ส่ง birthdate มาให้คำนวณเอง
        const realAge = calculateAge(response.data.birthdate);
        setAge(realAge);
      } else {
        setAge(null);
      }
    } catch (error: any) {
      console.warn(
        "fetchUserProfile error:",
        error?.response?.status,
        error?.message,
      );
      setAge(null);
    } finally {
      setLoadingAge(false);
    }
  };

  const fetchEntries = async () => {
    setLoadingEntries(true);
    setEntriesError(null);
    try {
      const axiosInstance = (await import("../../../src/config/axiosInstance"))
        .default;

      // If there's no token, fetch public entries directly (avoid 401)
      if (!token) {
        try {
          const pub = await axios.get(`${BACKEND_URL}/diarysleep/public`, {
            headers: { Accept: "application/json" },
          });
          const arr = Array.isArray(pub.data) ? pub.data : [];
          const normalized = arr
            .map((it: any) => ({
              id: Number(it.id),
              note: it.note ?? "",
              start_date: safeIsoDate(it.start_date),
              end_date: safeIsoDate(it.end_date),
              sleep_time: safeHHMM(it.sleep_time),
              wake_time: safeHHMM(it.wake_time),
              actual_sleep_start: it.actual_sleep_start ?? null,
              actual_wake_time: it.actual_wake_time ?? null,
              total_sleep_minutes:
                typeof it.total_sleep_minutes === "number"
                  ? it.total_sleep_minutes
                  : it.total_sleep_minutes
                    ? Number(it.total_sleep_minutes)
                    : null,
              user_id:
                typeof it.user_id !== "undefined" ? Number(it.user_id) : null,
              user_name: it.user_name ?? undefined,
              image_url: it.image_url ?? undefined,
            }))
            .sort((a: DiaryItem, b: DiaryItem) => {
              const da = a.start_date ?? "";
              const db = b.start_date ?? "";
              return db.localeCompare(da);
            });
          setEntries(normalized);
          return;
        } catch {
          setEntries([]);
          setEntriesError("กรุณาเข้าสู่ระบบเพื่อดูบันทึกส่วนตัว");
          return;
        }
      }

      // Try authenticated endpoint first (axiosInstance attaches token if available)
      try {
        const resp = await axiosInstance.get<DiaryItem[]>("/diarysleep");
        const arr = Array.isArray(resp.data) ? resp.data : [];
        const normalized: DiaryItem[] = arr
          .map((it: any) => ({
            id: Number(it.id),
            note: it.note ?? "",
            start_date: safeIsoDate(it.start_date),
            end_date: safeIsoDate(it.end_date),
            sleep_time: safeHHMM(it.sleep_time),
            wake_time: safeHHMM(it.wake_time),
            actual_sleep_start: it.actual_sleep_start ?? null,
            actual_wake_time: it.actual_wake_time ?? null,
            total_sleep_minutes:
              typeof it.total_sleep_minutes === "number"
                ? it.total_sleep_minutes
                : it.total_sleep_minutes
                  ? Number(it.total_sleep_minutes)
                  : null,
            user_id:
              typeof it.user_id !== "undefined" ? Number(it.user_id) : null,
            user_name: it.user_name ?? undefined,
            image_url: it.image_url ?? undefined,
          }))
          .sort((a, b) => {
            const da = a.start_date ?? "";
            const db = b.start_date ?? "";
            return db.localeCompare(da);
          });
        setEntries(normalized);
        computeStats(normalized);
        computeStats(normalized);
        return;
      } catch (err: any) {
        // If 401, quietly fallback to public endpoint and do not log 401 to console
        if (err?.response?.status === 401) {
          try {
            const pub = await axios.get(`${BACKEND_URL}/diarysleep/public`, {
              headers: { Accept: "application/json" },
            });
            const arr = Array.isArray(pub.data) ? pub.data : [];
            const normalized = arr
              .map((it: any) => ({
                id: Number(it.id),
                note: it.note ?? "",
                start_date: safeIsoDate(it.start_date),
                end_date: safeIsoDate(it.end_date),
                sleep_time: safeHHMM(it.sleep_time),
                wake_time: safeHHMM(it.wake_time),
                actual_sleep_start: it.actual_sleep_start ?? null,
                actual_wake_time: it.actual_wake_time ?? null,
                total_sleep_minutes:
                  typeof it.total_sleep_minutes === "number"
                    ? it.total_sleep_minutes
                    : it.total_sleep_minutes
                      ? Number(it.total_sleep_minutes)
                      : null,
                user_id:
                  typeof it.user_id !== "undefined" ? Number(it.user_id) : null,
                user_name: it.user_name ?? undefined,
                image_url: it.image_url ?? undefined,
              }))
              .sort((a: DiaryItem, b: DiaryItem) => {
                const da = a.start_date ?? "";
                const db = b.start_date ?? "";
                return db.localeCompare(da);
              });
            setEntries(normalized);
            computeStats(normalized);
            setEntriesError("กรุณาเข้าสู่ระบบเพื่อดูบันทึกส่วนตัว");
            return;
          } catch {
            setEntries([]);
            computeStats([]);
            computeStats([]);
            computeStats([]);
            setEntriesError("กรุณาเข้าสู่ระบบเพื่อดูบันทึกส่วนตัว");
            return;
          }
        }
        // other errors: show generic message
        setEntriesError("ไม่สามารถโหลดบันทึกการนอนได้ในขณะนี้");
        return;
      }
    } finally {
      setLoadingEntries(false);
    }
  };

  const scheduleNotification = async (title: string, time: Date) => {
    try {
      if (Platform.OS === "android" && Platform.Version >= 33) {
        try {
          const has = await PermissionsAndroid.check(
            PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS,
          );
          if (!has) {
            const granted = await PermissionsAndroid.request(
              PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS,
            );
            if (granted !== PermissionsAndroid.RESULTS.GRANTED) {
              console.warn("POST_NOTIFICATIONS permission not granted");
            }
          }
        } catch (err) {
          console.warn("POST_NOTIFICATIONS check failed", err);
        }
      }

      const triggerDate = new Date(
        time instanceof Date ? time.getTime() : new Date(time).getTime(),
      );
      const now = new Date();
      if (triggerDate.getTime() <= now.getTime()) {
        triggerDate.setDate(triggerDate.getDate() + 1);
      }

      const id = `local-${triggerDate.getTime()}`;
      // In Expo Go on Android, remote push functionality is removed (SDK 53+).
      // Avoid calling into expo-notifications in Expo Go; instead rely on
      // foreground timer + saved scheduled list as a fallback for development.
      if (isExpoGo) {
        // add scheduled entry and set foreground timer only
        const scheduled: ScheduledNotif = {
          id,
          title,
          dateIso: triggerDate.toISOString(),
        };
        await addScheduled(scheduled);
        scheduleForegroundTimer(id, title, triggerDate);
        return;
      }

      let Notifications: any = null;
      try {
        Notifications = await import("expo-notifications");
      } catch (e) {
        Notifications = null;
      }

      if (
        Notifications &&
        typeof Notifications.scheduleNotificationAsync === "function"
      ) {
        try {
          await Notifications.setNotificationHandler({
            handleNotification: async () => ({
              shouldShowBanner: true,
              shouldShowList: true,
              shouldPlaySound: true,
              shouldSetBadge: false,
            }),
          });
        } catch (e) {}

        await createAndroidNotificationChannel();

        try {
          await Notifications.scheduleNotificationAsync({
            content: {
              title,
              body: `ถึงเวลา ${title} แล้ว`,
              sound: "default",
              channelId: ANDROID_NOTIFICATION_CHANNEL_ID,
            },
            trigger: { type: "date", date: triggerDate },
          });
        } catch (e) {
          console.warn("system schedule failed", e);
        }
      } else {
        console.warn(
          "expo-notifications unavailable; relying on foreground modal timer only",
        );
      }

      const scheduled: ScheduledNotif = {
        id,
        title,
        dateIso: triggerDate.toISOString(),
      };
      await addScheduled(scheduled);
      scheduleForegroundTimer(id, title, triggerDate);
    } catch (err) {
      console.error("scheduleNotification error", err);
      Alert.alert("ไม่สามารถตั้งการแจ้งเตือนได้", String(err));
    }
  };

  const ensureTimesAreValid = () => {
    if (sleepTime.getTime() === wakeTime.getTime()) return false;
    return true;
  };

  const handleAcceptSound = async () => {
    try {
      await AsyncStorage.setItem(SOUND_ASKED_KEY, "1");
      setShowSoundModal(false);

      if (Platform.OS === "android" && Platform.Version >= 33) {
        try {
          const has = await PermissionsAndroid.check(
            PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS,
          );
          if (!has) {
            const granted = await PermissionsAndroid.request(
              PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS,
            );
            if (granted !== PermissionsAndroid.RESULTS.GRANTED) {
              Alert.alert(
                "ไม่ได้รับอนุญาต",
                "ต้องอนุญาตการแจ้งเตือน (POST_NOTIFICATIONS) เพื่อรับการแจ้งเตือน",
              );
              return;
            }
          }
        } catch (err) {
          console.warn("POST_NOTIFICATIONS request failed", err);
        }
      }

      if (isExpoGo) return;

      try {
        const Notifications = await import("expo-notifications");
        const { status } = await Notifications.getPermissionsAsync();
        if (status !== "granted") {
          const req = await Notifications.requestPermissionsAsync({
            ios: { allowAlert: true, allowSound: true, allowBadge: true },
          });
          if (req.status !== "granted") {
            Alert.alert(
              "ไม่ได้รับสิทธิ์แจ้งเตือน",
              "โปรดอนุญาตการแจ้งเตือนในตั้งค่าเพื่อให้เสียงแจ้งเตือนทำงาน",
              [
                { text: "ยกเลิก", style: "cancel" },
                { text: "ไปที่ตั้งค่า", onPress: () => Linking.openSettings() },
              ],
            );
            return;
          }
        }
      } catch (err) {
        console.warn("notification permission error", err);
      }
    } catch (e) {
      console.error("handleAcceptSound error", e);
      setShowSoundModal(false);
    }
  };

  const handleDeclineSound = async () => {
    try {
      await AsyncStorage.setItem(SOUND_ASKED_KEY, "1");
    } catch {}
    setShowSoundModal(false);
    Alert.alert(
      "ปิดเสียงแจ้งเตือน",
      "คุณสามารถเปิดเสียงแจ้งเตือนได้จากการตั้งค่าแอปหากเปลี่ยนใจ",
      [
        { text: "ไปที่ตั้งค่า", onPress: () => Linking.openSettings() },
        { text: "ปิด", style: "cancel" },
      ],
    );
  };

  const handleSubmit = async () => {
    if (submitting) return;
    if (!token) {
      Alert.alert("ไม่พบการเข้าสู่ระบบ", "กรุณาเข้าสู่ระบบก่อนบันทึก");
      return;
    }
    if (!ensureTimesAreValid()) {
      Alert.alert("เวลาผิดพลาด", "เวลานอนและเวลาตื่นห้ามเท่ากัน");
      return;
    }

    setSubmitting(true);
    try {
      const payload: any = {
        note,
        start_date: formatDate(date),
        end_date: formatDate(date),
        sleep_time: formatTime(sleepTime),
        wake_time: formatTime(wakeTime),
      };
      if (userId !== null) payload.user_id = userId;

      const resp = await axios.post(`${BACKEND_URL}/diarysleep`, payload, {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
      });

      const diaryId = resp?.data?.id ?? resp?.data ?? null;
      if (diaryId) {
        try {
          await AsyncStorage.setItem(LAST_DIARY_ID_KEY, String(diaryId));
        } catch {}
      }

      Alert.alert("บันทึกสำเร็จ", "เวลานอนของคุณถูกสร้างแล้ว");
      setNote("");
      await fetchEntries();

      const sleepNotifyTime = new Date(date);
      sleepNotifyTime.setHours(sleepTime.getHours());
      sleepNotifyTime.setMinutes(sleepTime.getMinutes());
      sleepNotifyTime.setSeconds(0);
      await scheduleNotification("เริ่มนอน", sleepNotifyTime);

      const wakeNotifyTime = new Date(date);
      wakeNotifyTime.setHours(wakeTime.getHours());
      wakeNotifyTime.setMinutes(wakeTime.getMinutes());
      wakeNotifyTime.setSeconds(0);
      await scheduleNotification("ปลุก", wakeNotifyTime);
    } catch (e) {
      console.error("submit diary error:", e);
      const msg =
        (e as any)?.response?.data?.detail ||
        (e as any)?.message ||
        "เกิดข้อผิดพลาดในการบันทึก";
      Alert.alert("บันทึกล้มเหลว", String(msg));
    } finally {
      setSubmitting(false);
    }
  };

  const handleStartSleepFromModal = async () => {
    const now = Date.now();
    setSleepStartTs(now);
    try {
      await AsyncStorage.setItem("sleep_start_ts", String(now));
    } catch (e) {}
    setPendingNotification(null);
    Alert.alert("เริ่มนอน", "บันทึกเวลาเริ่มนอนแล้ว");
  };

  const handleSnoozeFromModal = async () => {
    if (!pendingNotification) return;
    const snoozeDate = new Date(Date.now() + 1 * 60 * 1000);
    await scheduleNotification(
      pendingNotification.title || "การแจ้งเตือน",
      snoozeDate,
    );
    setPendingNotification(null);
    Alert.alert("เลื่อน", "เลื่อนอีก 1 นาที");
  };

  const handleWakeFromModal = async () => {
    if (!pendingNotification) return;
    let startTs = sleepStartTs;
    if (!startTs) {
      const stored = await AsyncStorage.getItem("sleep_start_ts");
      if (stored) startTs = Number(stored);
    }

    const wakeTs = Date.now();
    let message = "ปลุก";
    if (startTs) {
      const diffMs = wakeTs - startTs;
      const totalMinutes = Math.max(0, Math.floor(diffMs / 60000));
      const hours = Math.floor(totalMinutes / 60);
      const minutes = totalMinutes % 60;
      message = `เวลานอนทั้งหมด ${hours} ชั่วโมง ${minutes} นาที`;

      try {
        await AsyncStorage.removeItem("sleep_start_ts");
      } catch {}
      setSleepStartTs(null);
    }

    try {
      const diaryIdStored = await AsyncStorage.getItem(LAST_DIARY_ID_KEY);
      if (token && diaryIdStored) {
        const diaryId = Number(diaryIdStored);
        const payload = {
          actual_sleep_start: startTs ? new Date(startTs).toISOString() : null,
          actual_wake_time: new Date(wakeTs).toISOString(),
          total_sleep_minutes: startTs
            ? Math.floor((wakeTs - startTs) / 60000)
            : null,
        };
        await axios
          .put(`${BACKEND_URL}/diarysleep/${diaryId}`, payload, {
            headers: { Authorization: `Bearer ${token}` },
          })
          .catch(() => {});
        await fetchEntries();
      }
    } catch (err) {
      console.error("wake backend error", err);
    }

    setPendingNotification(null);
    Alert.alert("ปลุก", message);
  };

  const onChangeSleep = (_: any, selected?: Date) => {
    setShowSleepPicker(Platform.OS === "ios");
    if (selected) setSleepTime(selected);
  };

  const onChangeWake = (_: any, selected?: Date) => {
    setShowWakePicker(Platform.OS === "ios");
    if (selected) setWakeTime(selected);
  };

  const onChangeDate = (_: any, selected?: Date) => {
    setShowDatePicker(Platform.OS === "ios");
    if (selected) {
      setDate(selected);
      setDisplayDate(formatDate(selected));
    }
  };

  function openEdit(entry: DiaryItem) {
    setEditingEntry(entry);
    setEditingNote(entry.note ?? "");
    setEditModalVisible(true);
  }

  async function saveEdit() {
    if (!editingEntry || !token) return;
    setSavingEdit(true);
    try {
      const payload: any = {
        note: editingNote,
      };
      await axios.put(`${BACKEND_URL}/diarysleep/${editingEntry.id}`, payload, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setEntries((prev) =>
        prev.map((p) =>
          p.id === editingEntry.id ? { ...p, note: editingNote } : p,
        ),
      );
      setEditModalVisible(false);
      setEditingEntry(null);
      Alert.alert("บันทึกสำเร็จ", "แก้ไขบันทึกสำเร็จ");
    } catch (err) {
      console.error("saveEdit error", err);
      Alert.alert("ล้มเหลว", "ไม่สามารถบันทึกการแก้ไขได้");
    } finally {
      setSavingEdit(false);
    }
  }

  async function deleteEntry(entryId: number) {
    if (!token) return;
    Alert.alert("ยืนยัน", "ต้องการลบบันทึกนี้หรือไม่?", [
      { text: "ยกเลิก", style: "cancel" },
      {
        text: "ลบ",
        style: "destructive",
        onPress: async () => {
          try {
            await axios.delete(`${BACKEND_URL}/diarysleep/${entryId}`, {
              headers: { Authorization: `Bearer ${token}` },
            });
            await fetchEntries();
            Alert.alert("ลบแล้ว", "ลบบันทึกสำเร็จ");
          } catch (err) {
            console.error("deleteEntry error", err);
            Alert.alert("ล้มเหลว", "ไม่สามารถลบบันทึกได้");
          }
        },
      },
    ]);
  }

  function renderBannerCard({ item }: { item: DiaryItem }) {
    const evaluation = evaluateSleepForRecord(item.total_sleep_minutes);
    return (
      <View style={styles.bannerCard}>
        <View style={styles.bannerBody}>
          <Text style={styles.noteText}>{item.note ?? "ไม่มีบันทึก"}</Text>

          <View style={{ marginTop: 10 }}>
            <Text style={styles.smallLabel}>วันที่</Text>
            <Text style={{ color: "#666" }}>{item.start_date ?? "-"}</Text>
            <Text style={styles.smallLabel}>เวลานอน</Text>
            <Text style={{ color: "#666" }}>{item.sleep_time ?? "-"}</Text>
            <Text style={styles.smallLabel}>เวลาตื่น</Text>
            <Text style={{ color: "#666" }}>{item.wake_time ?? "-"}</Text>
            <Text style={styles.smallLabel}>เวลานอนรวม</Text>
            <Text style={{ color: "#007AFF", fontWeight: "700" }}>
              {item.total_sleep_minutes !== null &&
              typeof item.total_sleep_minutes !== "undefined"
                ? `${item.total_sleep_minutes} นาที (${(item.total_sleep_minutes / 60).toFixed(1)} ชม.)`
                : "-"}
            </Text>

            {evaluation && (
              <View
                style={[
                  styles.evalBadge,
                  { backgroundColor: evaluation.bgColor },
                ]}
              >
                <Text style={[styles.evalText, { color: evaluation.color }]}>
                  ผลประเมิน: {evaluation.text}
                </Text>
              </View>
            )}
          </View>
        </View>

        <View style={styles.bannerActions}>
          <TouchableOpacity
            style={styles.actionBtn}
            onPress={() => openEdit(item)}
          >
            <Text style={styles.actionText}>แก้ไข</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.actionBtn, { borderColor: "#ff3b30" }]}
            onPress={() => deleteEntry(item.id)}
          >
            <Text style={[styles.actionText, { color: "#ff3b30" }]}>ลบ</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>บันทึกไดอารี่การนอน</Text>

      {/* recommendation about average sleep */}
      <View
        style={{
          padding: 10,
          backgroundColor: "#e0f7fa",
          borderRadius: 8,
          marginBottom: 12,
        }}
      >
        <Text style={{ color: "#00796b", fontSize: 16 }}>
          {age !== null && age >= 0
            ? // ดึงค่า min และ max จากฟังก์ชันโดยใส่อายุที่คำนวณได้แบบเป๊ะๆ เข้าไป
              `แนะนำให้พักผ่อนเฉลี่ย ${getSleepRecommendation(age).min}-${getSleepRecommendation(age).max} ชั่วโมงต่อวัน`
            : // แสดงข้อความนี้ระหว่างรอระบบคำนวณ หรือกรณีที่ผู้ใช้ยังไม่เคยกรอกวันเกิด
              "กำลังคำนวณคำแนะนำการพักผ่อน..."}
        </Text>
        {avgSleepMinutes !== null && (
          <Text style={{ color: "#004d40", marginTop: 4 }}>
            เวลานอนเฉลี่ยของคุณ: {Math.round(avgSleepMinutes)} นาที (
            {(avgSleepMinutes / 60).toFixed(1)} ชม.)
            {"\n"}คุณภาพการนอน: {sleepQuality}
          </Text>
        )}
      </View>

      {/* ...existing code... */}

      <TouchableOpacity
        onPress={() => setShowDatePicker(true)}
        style={styles.dateRow}
      >
        <Text style={styles.label}>วันที่: {displayDate}</Text>
      </TouchableOpacity>

      <View style={styles.timeRow}>
        <View style={styles.timeBox}>
          <Text style={styles.label}>เวลานอน</Text>
          <TouchableOpacity
            onPress={() => timeEnabled && setShowSleepPicker(true)}
            disabled={!timeEnabled}
          >
            <Text style={[styles.timeText, !timeEnabled && { color: "#aaa" }]}>
              {formatTime(sleepTime)}
            </Text>
          </TouchableOpacity>
        </View>

        <View style={styles.timeBox}>
          <Text style={styles.label}>เวลาตื่น</Text>
          <TouchableOpacity
            onPress={() => timeEnabled && setShowWakePicker(true)}
            disabled={!timeEnabled}
          >
            <Text style={[styles.timeText, !timeEnabled && { color: "#aaa" }]}>
              {formatTime(wakeTime)}
            </Text>
          </TouchableOpacity>
        </View>

        <View style={styles.switchBox}>
          <Switch value={timeEnabled} onValueChange={setTimeEnabled} />
        </View>
      </View>

      <Text style={styles.label}>โน้ตเพิ่มเติม</Text>
      <TextInput
        style={styles.input}
        placeholder="เช่น นอนหลับดีมาก"
        value={note}
        onChangeText={setNote}
        multiline
      />

      <TouchableOpacity
        style={[styles.button, submitting && styles.buttonDisabled]}
        onPress={handleSubmit}
        disabled={submitting}
      >
        <Text style={styles.buttonText}>
          {submitting ? "กำลังบันทึก..." : "สร้าง"}
        </Text>
      </TouchableOpacity>

      <View style={{ marginTop: 18 }}>
        <View
          style={{
            flexDirection: "row",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <Text style={[styles.label, { marginBottom: 8 }]}>รายการบันทึก</Text>
          <TouchableOpacity onPress={fetchEntries}>
            <Text style={{ color: "#007AFF" }}>
              {loadingEntries ? "..." : "รีเฟรช"}
            </Text>
          </TouchableOpacity>
        </View>

        {loadingEntries ? (
          <ActivityIndicator />
        ) : entriesError ? (
          <View
            style={{ padding: 12, backgroundColor: "#fdecea", borderRadius: 8 }}
          >
            <Text style={{ color: "#b00020" }}>{entriesError}</Text>
            <TouchableOpacity onPress={fetchEntries} style={{ marginTop: 8 }}>
              <Text style={{ color: "#007AFF" }}>ลองอีกครั้ง</Text>
            </TouchableOpacity>
          </View>
        ) : entries.length > 0 ? (
          <FlatList
            data={entries}
            keyExtractor={(it) => String(it.id)}
            renderItem={renderBannerCard}
            ItemSeparatorComponent={() => <View style={{ height: 12 }} />}
            contentContainerStyle={{ paddingBottom: 40 }}
          />
        ) : (
          <View
            style={{ padding: 12, backgroundColor: "#f0f0f0", borderRadius: 8 }}
          >
            <Text>ยังไม่มีบันทึกการนอน</Text>
            <TouchableOpacity onPress={fetchEntries} style={{ marginTop: 8 }}>
              <Text style={{ color: "#007AFF" }}>โหลดรายการ</Text>
            </TouchableOpacity>
          </View>
        )}
      </View>

      {showDatePicker && (
        <DateTimePicker
          value={date}
          mode="date"
          display={Platform.OS === "ios" ? "spinner" : "default"}
          onChange={onChangeDate}
        />
      )}

      {showSleepPicker && (
        <DateTimePicker
          value={sleepTime}
          mode="time"
          is24Hour
          display={Platform.OS === "ios" ? "spinner" : "clock"}
          onChange={onChangeSleep}
        />
      )}

      {showWakePicker && (
        <DateTimePicker
          value={wakeTime}
          mode="time"
          is24Hour
          display={Platform.OS === "ios" ? "spinner" : "clock"}
          onChange={onChangeWake}
        />
      )}

      <Modal
        visible={!!pendingNotification}
        transparent
        animationType="slide"
        onRequestClose={() => setPendingNotification(null)}
      >
        <View style={modalStyles.backdrop}>
          <View style={modalStyles.modal}>
            <Text style={modalStyles.modalTitle}>
              {pendingNotification?.title || "การแจ้งเตือน"}
            </Text>
            <Text style={modalStyles.modalBody}>
              {pendingNotification?.body}
            </Text>

            <View style={modalStyles.actions}>
              <TouchableOpacity
                style={[modalStyles.actionButton, modalStyles.actionPrimary]}
                onPress={() => {
                  const title = pendingNotification?.title || "";
                  if (title.includes("เริ่ม") || title.includes("นอน"))
                    handleStartSleepFromModal();
                  else handleWakeFromModal();
                }}
              >
                <Text style={modalStyles.actionPrimaryText}>
                  {(pendingNotification?.title || "").includes("เริ่ม")
                    ? "เริ่มนอน"
                    : "ปลุก"}
                </Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={[modalStyles.actionButton, modalStyles.actionOutline]}
                onPress={handleSnoozeFromModal}
              >
                <Text style={modalStyles.actionOutlineText}>เลื่อน 1 นาที</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={[modalStyles.actionButton, modalStyles.actionCancel]}
                onPress={() => setPendingNotification(null)}
              >
                <Text style={modalStyles.actionCancelText}>ปิด</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      <Modal
        visible={showSoundModal}
        transparent
        animationType="fade"
        onRequestClose={() => setShowSoundModal(false)}
      >
        <View style={modalStyles.backdrop}>
          <View style={[modalStyles.modal, { alignItems: "center" }]}>
            <Text style={[modalStyles.modalTitle, { textAlign: "center" }]}>
              ขออนุญาตใช้เสียงแจ้งเตือน
            </Text>
            <Text style={[modalStyles.modalBody, { textAlign: "center" }]}>
              แอปต้องการส่งการแจ้งเตือนพร้อมเสียงเพื่อเตือนเวลานอน-ตื่น
              ต้องการเปิดใช้งานเสียงแจ้งเตือนหรือไม่
            </Text>

            <View
              style={{
                flexDirection: "row",
                marginTop: 8,
                width: "100%",
                justifyContent: "space-between",
              }}
            >
              <TouchableOpacity
                style={[
                  modalStyles.actionButton,
                  modalStyles.actionOutline,
                  { flex: 1, marginRight: 8 },
                ]}
                onPress={handleAcceptSound}
              >
                <Text style={modalStyles.actionOutlineText}>อนุญาต</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={[
                  modalStyles.actionButton,
                  modalStyles.actionCancel,
                  { flex: 1 },
                ]}
                onPress={handleDeclineSound}
              >
                <Text style={modalStyles.actionCancelText}>ไม่ตอนนี้</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      <Modal
        visible={editModalVisible}
        transparent
        animationType="slide"
        onRequestClose={() => setEditModalVisible(false)}
      >
        <KeyboardAvoidingView
          behavior={Platform.OS === "ios" ? "padding" : undefined}
          style={styles.modalWrapper}
        >
          <View style={styles.modalBackdrop} />
          <View style={styles.modalContainer}>
            <Text style={styles.modalTitle}>แก้ไขบันทึก</Text>
            <TextInput
              value={editingNote}
              onChangeText={setEditingNote}
              style={styles.modalInput}
              multiline
            />
            <View style={styles.modalActions}>
              <TouchableOpacity
                onPress={() => {
                  setEditModalVisible(false);
                  setEditingEntry(null);
                }}
                style={[styles.modalBtn, styles.modalCancel]}
              >
                <Text style={styles.modalCancelText}>ยกเลิก</Text>
              </TouchableOpacity>
              <TouchableOpacity
                onPress={saveEdit}
                style={[styles.modalBtn, styles.modalSave]}
                disabled={savingEdit}
              >
                {savingEdit ? (
                  <ActivityIndicator color="#fff" />
                ) : (
                  <Text style={styles.modalSaveText}>บันทึก</Text>
                )}
              </TouchableOpacity>
            </View>
          </View>
        </KeyboardAvoidingView>
      </Modal>
    </View>
  );
}

/* ---------- Styles ---------- */
const styles = StyleSheet.create({
  container: { flex: 1, padding: 12, backgroundColor: "#fff" },
  title: { fontSize: 18, fontWeight: "700", marginBottom: 12 },
  label: { fontSize: 14, color: "#333", marginBottom: 6 },
  input: {
    borderWidth: 1,
    borderColor: "#e0e0e0",
    borderRadius: 8,
    padding: 10,
    minHeight: 44,
    textAlignVertical: "top",
  },
  dateRow: { marginBottom: 12, alignItems: "center" },
  timeRow: { flexDirection: "row", alignItems: "center", marginBottom: 12 },
  timeBox: { flex: 1 },
  switchBox: { width: 56, alignItems: "center" },
  timeText: { fontSize: 16, color: "#111", fontWeight: "600" },
  button: {
    backgroundColor: "#007AFF",
    padding: 12,
    borderRadius: 8,
    alignItems: "center",
    marginTop: 12,
  },
  buttonDisabled: { opacity: 0.6 },
  buttonText: { color: "#fff", fontWeight: "700" },
  bannerCard: {
    flexDirection: "row",
    padding: 12,
    backgroundColor: "#fff",
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#eee",
  },
  bannerBody: { flex: 1 },
  bannerActions: { justifyContent: "space-between", alignItems: "flex-end" },
  noteText: { fontSize: 14, color: "#222" },
  smallLabel: { fontSize: 12, color: "#888", marginTop: 8 },
  actionBtn: {
    paddingVertical: 6,
    paddingHorizontal: 10,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: "#007AFF",
    marginBottom: 6,
  },
  actionText: { color: "#007AFF", fontWeight: "600" },

  evalBadge: {
    alignSelf: "stretch",
    padding: 10,
    borderRadius: 8,
    alignItems: "center",
    marginTop: 8,
  },
  evalText: { fontSize: 14, fontWeight: "bold" },

  modalWrapper: { flex: 1 },
  modalBackdrop: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: "rgba(0,0,0,0.4)",
  },
  modalContainer: {
    margin: 24,
    backgroundColor: "#fff",
    borderRadius: 12,
    padding: 16,
    zIndex: 10,
  },
  modalTitle: { fontSize: 16, fontWeight: "700", marginBottom: 8 },
  modalInput: {
    borderWidth: 1,
    borderColor: "#e0e0e0",
    borderRadius: 8,
    padding: 10,
    minHeight: 80,
    textAlignVertical: "top",
  },
  modalActions: {
    flexDirection: "row",
    justifyContent: "flex-end",
    marginTop: 12,
  },
  modalBtn: {
    paddingVertical: 10,
    paddingHorizontal: 14,
    borderRadius: 8,
    marginLeft: 8,
  },
  modalCancel: { backgroundColor: "#f0f0f0" },
  modalSave: { backgroundColor: "#007AFF" },
  modalCancelText: { color: "#333" },
  modalSaveText: { color: "#fff" },
});

const modalStyles = StyleSheet.create({
  backdrop: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.4)",
    justifyContent: "center",
    alignItems: "center",
  },
  modal: {
    width: "92%",
    backgroundColor: "#fff",
    borderRadius: 14,
    padding: 18,
    shadowColor: "#000",
    shadowOpacity: 0.12,
    shadowRadius: 12,
    elevation: 8,
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: "800",
    marginBottom: 6,
    color: "#111",
  },
  modalBody: { fontSize: 14, color: "#444", marginBottom: 12 },
  actions: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginTop: 8,
  },

  // base action button
  actionButton: {
    minWidth: 92,
    paddingVertical: 10,
    paddingHorizontal: 14,
    borderRadius: 10,
    alignItems: "center",
    justifyContent: "center",
    marginHorizontal: 6,
  },

  // primary (filled)
  actionPrimary: {
    backgroundColor: "#007AFF",
    shadowColor: "#007AFF",
    shadowOpacity: 0.18,
    shadowOffset: { width: 0, height: 6 },
    shadowRadius: 12,
    elevation: 6,
  },
  actionPrimaryText: {
    color: "#fff",
    fontWeight: "800",
    fontSize: 15,
  },

  // outline (secondary)
  actionOutline: {
    backgroundColor: "#fff",
    borderWidth: 1,
    borderColor: "#d0d7de",
  },
  actionOutlineText: {
    color: "#333",
    fontWeight: "700",
    fontSize: 14,
  },

  // cancel (muted)
  actionCancel: {
    backgroundColor: "#f5f6f8",
    borderWidth: 0,
  },
  actionCancelText: {
    color: "#666",
    fontWeight: "700",
    fontSize: 14,
  },
});
