// app/(member)/QuestSleepScreen.tsx
import AsyncStorage from "@react-native-async-storage/async-storage";
import React, { useCallback, useEffect, useState } from "react";
import {
    ActivityIndicator,
    Alert,
    Button,
    Pressable,
    ScrollView,
    StyleSheet,
    Text,
    View,
} from "react-native";

/**
 * QuestSleepScreen (member)
 *
 * - เมื่อกดยืนยันรับเควส: รายการที่ถูก "รับ" จะกลายเป็นสถานะ "in_progress"
 *   รายการที่ไม่ได้รับจะกลายเป็น "rejected"
 * - หลังยืนยันแล้ว จะล็อกการเปลี่ยนสถานะรับ/ปฏิเสธ
 * - สำหรับแต่ละรายการที่เป็น in_progress หรือ completed จะมีปุ่ม "ทำเสร็จ"/"ทำไม่เสร็จ"
 * - ปุ่มหลักด้านล่างเป็น "ยืนยันรับเควส" (เป็นการบันทึกด้วย)
 *
 * ปรับปรุงเพิ่มเติมตามคำขอ:
 * - เก็บสถานะของแต่ละรายการ (in_progress / completed / rejected / accepted) ลง AsyncStorage
 *   แยกตามผู้ใช้และวัน (progress per user per day)
 * - โหลดสถานะที่บันทึกไว้เมื่อเปิดหน้าจอใหม่ เพื่อให้สถานะ "ทำเสร็จ" คงอยู่เมื่อเปิดอีกครั้ง
 */

const BACKEND = "http://192.168.1.2:8000"; // ปรับตาม environment ของคุณ
const ACCEPTED_STATE_KEY_BASE = "flashsleep:accepted_state"; // base key; จะผนวก user id
const TODAY_SELECTION_KEY_BASE = "flashsleep:today_selection"; // base key; จะผนวก user id
const PROGRESS_KEY_BASE = "flashsleep:progress"; // new: per-user per-day progress key

type PeriodKey = "morning" | "afternoon" | "evening";
type TaskItem = {
  id: string | number;
  label: string;
  quest_id?: number | null;
  status?: "pending" | "accepted" | "in_progress" | "completed" | "rejected";
  score?: number; // fixed 20 when completed
};

export default function QuestSleepScreen() {
  // -------------------------
  // Manual save progress to backend (custom API)
  // -------------------------

  const handleSaveProgress = async () => {
    try {
      const token = await AsyncStorage.getItem("token");
      if (!token) return;

      // 1. จัดรูปแบบข้อมูลให้ตรงกับที่ Backend ต้องการ
      // (ต้องแบ่งเป็น morning, afternoon, evening)
      const payloadData = {
        morning: (periods.morning || []).map((q) => ({
          ...q,
          status: q.status || "pending",
        })),
        afternoon: (periods.afternoon || []).map((q) => ({
          ...q,
          status: q.status || "pending",
        })),
        evening: (periods.evening || []).map((q) => ({
          ...q,
          status: q.status || "pending",
        })),
      };

      // 2. ส่งไป Backend
      const res = await fetch(`${BACKEND}/api/quest-progress`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          quest_id: 1, // หรือไอดีของ quest หลักถ้ามี
          items: payloadData, // ส่ง data ที่จัดกลุ่มแล้วไป
        }),
      });

      if (res.ok) {
        console.log("บันทึกคะแนนลง Database สำเร็จ!");
        // 3. หลังจากบันทึกเสร็จ ให้โหลด Leaderboard ใหม่ทันที!
        fetchLeaderboard();
      } else {
        console.log("บันทึกคะแนนล้มเหลว", await res.text());
      }
    } catch (error) {
      console.warn("error saving progress:", error);
    }
  };
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [userProfile, setUserProfile] = useState<any | null>(null);

  const [periods, setPeriods] = useState<Record<PeriodKey, TaskItem[]>>({
    morning: [],
    afternoon: [],
    evening: [],
  });

  // 🏆 Leaderboard State (new type for compatibility)
  type LeaderboardEntry = {
    user_id: number;
    name: string;
    total_score: number;
  };
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [loadingLeaderboard, setLoadingLeaderboard] = useState(false);

  const fetchLeaderboard = async () => {
    try {
      setLoadingLeaderboard(true);

      const token = await AsyncStorage.getItem("token");
      // แก้ไข: ถ้าไม่มี token ให้ปิดสถานะโหลดด้วย ไม่รั้นมันจะค้างยาว
      if (!token) {
        setLoadingLeaderboard(false);
        return;
      }

      const res = await fetch(`${BACKEND}/leaderboard`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (res.ok) {
        const data = await res.json();
        console.log("ข้อมูลกระดานผู้นำที่ได้จาก Backend: ", data); // <-- เพิ่มบรรทัดนี้เพื่อเช็คข้อมูล
        setLeaderboard(data);
      } else {
        console.log("ดึงข้อมูลไม่สำเร็จ Status:", res.status);
      }
    } catch (error) {
      console.warn("fetchLeaderboard error:", error);
    } finally {
      setLoadingLeaderboard(false);
    }
  };

  // สถานะการยืนยันรับ (ล็อกการเปลี่ยน accept/reject)
  const [confirmedAccept, setConfirmedAccept] = useState(false);
  const [acceptStartTime, setAcceptStartTime] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const u = await loadUserProfile();
      await buildDailyPeriods(u);
      await loadAcceptedState(u);
      await loadProgress(u);
      // 📌 เพิ่ม fetchLeaderboard สำหรับ leaderboard ใหม่
      fetchLeaderboard();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const authHeaders = useCallback(async () => {
    const token = await AsyncStorage.getItem("token");
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }, []);

  async function loadUserProfile() {
    try {
      const raw =
        (await AsyncStorage.getItem("user")) ||
        (await AsyncStorage.getItem("profile"));
      if (raw) {
        try {
          const u = JSON.parse(raw);
          setUserProfile(u);
          return u;
        } catch {
          // ignore
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  // -------------------------
  // Helpers: date keys (ผูกกับ user)
  // -------------------------
  function getUserIdForKey(u?: any) {
    try {
      if (u && (u.id || u.user_id || u._id)) {
        return String(u.id ?? u.user_id ?? u._id);
      }
    } catch {}
    return "anon";
  }

  function acceptedStateKeyForUser(u?: any) {
    const uid = getUserIdForKey(u ?? userProfile);
    return `${ACCEPTED_STATE_KEY_BASE}:${uid}`;
  }

  function todaySelectionKeyForUser(u?: any) {
    const uid = getUserIdForKey(u ?? userProfile);
    const d = new Date();
    const dayKey = `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
    return `${TODAY_SELECTION_KEY_BASE}:${uid}:${dayKey}`;
  }

  function progressKeyForUser(u?: any) {
    const uid = getUserIdForKey(u ?? userProfile);
    const d = new Date();
    const dayKey = `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
    return `${PROGRESS_KEY_BASE}:${uid}:${dayKey}`;
  }

  function getTodayKey() {
    // legacy name kept for compatibility but we will use todaySelectionKeyForUser when storing
    const d = new Date();
    return `quest_day_${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
  }
  function getYesterdayKey() {
    const d = new Date();
    d.setDate(d.getDate() - 1);
    return `quest_day_${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
  }

  // -------------------------
  // Load accepted state (if saved and not expired) - per user
  // -------------------------
  async function loadAcceptedState(loadedUser?: any) {
    try {
      const key = acceptedStateKeyForUser(loadedUser);
      const raw = await AsyncStorage.getItem(key);
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (!saved) return;

      const {
        periods: savedPeriods,
        acceptStartTime: savedStartIso,
        confirmedAccept: savedConfirmed,
      } = saved;
      if (!savedStartIso || !savedConfirmed) return;

      const startMs = new Date(savedStartIso).getTime();
      const age = Date.now() - startMs;
      const DAY_MS = 24 * 60 * 60 * 1000;

      if (age < DAY_MS) {
        // ยังไม่ครบ 24 ชั่วโมง ให้กู้สถานะกลับมา
        setPeriods(savedPeriods);
        setConfirmedAccept(true);
        setAcceptStartTime(savedStartIso);
      } else {
        // เกิน 24 ชั่วโมงแล้ว ให้ลบสถานะเก่า
        await AsyncStorage.removeItem(key);
      }
    } catch (e) {
      console.warn("loadAcceptedState error", e);
    }
  }

  // -------------------------
  // Progress persistence (new)
  // - saveProgress: บันทึกสถานะ periods ลง AsyncStorage per-user-per-day
  // - loadProgress: โหลดและ merge กับ selection ที่สร้างขึ้น
  // -------------------------
  async function saveProgress(
    u?: any,
    currentPeriods?: Record<PeriodKey, TaskItem[]>,
  ) {
    try {
      const key = progressKeyForUser(u);
      const payload = {
        periods: currentPeriods ?? periods,
        savedAt: new Date().toISOString(),
      };
      await AsyncStorage.setItem(key, JSON.stringify(payload));
    } catch (e) {
      console.warn("saveProgress error", e);
    }
  }

  async function loadProgress(loadedUser?: any) {
    try {
      const key = progressKeyForUser(loadedUser);
      const raw = await AsyncStorage.getItem(key);
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (!saved || !saved.periods) return;

      // Merge saved statuses into current periods (match by id)
      setPeriods((current) => {
        const merged: Record<PeriodKey, TaskItem[]> = {
          morning: [],
          afternoon: [],
          evening: [],
        };
        for (const k of Object.keys(current) as PeriodKey[]) {
          const curArr = current[k] || [];
          const savedArr = saved.periods[k] || [];
          // build map from saved by id
          const savedMap = new Map<string, TaskItem>();
          for (const s of savedArr) {
            if (s && s.id != null) savedMap.set(String(s.id), s);
          }
          merged[k] = curArr.map((it) => {
            const s = savedMap.get(String(it.id));
            if (s && s.status) {
              // keep label/quest_id from current selection but apply saved status
              return {
                ...it,
                status: s.status,
                score: s.status === "completed" ? 20 : 0,
              };
            }
            return it;
          });
        }
        return merged;
      });
    } catch (e) {
      console.warn("loadProgress error", e);
    }
  }

  // -------------------------
  // Leaderboard: scan AsyncStorage for today's progress entries and compute total scores per user
  // -------------------------
  async function loadLeaderboard() {
    try {
      setLoadingLeaderboard(true);
      const allKeys = await AsyncStorage.getAllKeys();
      const d = new Date();
      const dayKey = `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
      const prefix = `${PROGRESS_KEY_BASE}:`;
      const matching = allKeys.filter(
        (k) => k.startsWith(prefix) && k.endsWith(`:${dayKey}`),
      );
      const rows: Array<{ uid: string; name?: string; score: number }> = [];
      for (const k of matching) {
        try {
          const raw = await AsyncStorage.getItem(k);
          if (!raw) continue;
          const parsed = JSON.parse(raw);
          const periodsObj = parsed?.periods || {};
          let total = 0;
          for (const p of ["morning", "afternoon", "evening"]) {
            const arr = periodsObj[p] || [];
            for (const it of arr) {
              if (it && it.status === "completed") {
                total += typeof it.score === "number" ? it.score : 20;
              }
            }
          }
          // extract uid from key: PROGRESS_KEY_BASE:uid:dayKey
          const parts = k.split(":");
          const uid = parts.length >= 3 ? parts[1] : k;
          rows.push({ uid, score: total });
        } catch (e) {
          // ignore parse errors
        }
      }
      // sort desc
      rows.sort((a, b) => b.score - a.score);
      // try to resolve current user's name
      const userRaw =
        (await AsyncStorage.getItem("user")) ||
        (await AsyncStorage.getItem("profile"));
      let currentName: string | undefined = undefined;
      if (userRaw) {
        try {
          const u = JSON.parse(userRaw);
          currentName =
            u?.name || u?.username || u?.displayName || u?.user_name;
        } catch {}
      }
      const rowsWithNames = rows.map((r) => ({
        ...r,
        name:
          r.uid === String(userProfile?.id ?? userProfile?.user_id)
            ? currentName
            : undefined,
      }));
      setLeaderboard(rowsWithNames);
    } catch (e) {
      console.warn("loadLeaderboard error", e);
    } finally {
      setLoadingLeaderboard(false);
    }
  }

  // -------------------------
  // Fetch quests and build pools
  // -------------------------
  async function buildDailyPeriods(loadedUser?: any) {
    setLoading(true);
    try {
      // --- 1. คำนวณช่วงอายุของผู้ใช้ ---
      const user = loadedUser || userProfile;
      let userGroup = "adult"; // ค่าเริ่มต้นกรณีไม่มีข้อมูล

      if (user) {
        if (user.age_group) {
          userGroup = user.age_group;
        } else if (user.age !== undefined && user.age !== null) {
          const age = Number(user.age);
          if (age <= 12) userGroup = "child";
          else if (age <= 19) userGroup = "teen";
          else if (age <= 59) userGroup = "adult";
          else userGroup = "senior";
        } else if (user.birthday) {
          const birthDate = new Date(user.birthday);
          const today = new Date();
          let age = today.getFullYear() - birthDate.getFullYear();
          const m = today.getMonth() - birthDate.getMonth();
          if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate()))
            age--;

          if (age <= 12) userGroup = "child";
          else if (age <= 19) userGroup = "teen";
          else if (age <= 59) userGroup = "adult";
          else userGroup = "senior";
        }
      }

      // ดูใน Terminal ว่าระบบดึงค่าวัยมาตรงไหม
      console.log("===> กลุ่มอายุของผู้ใช้ตอนนี้คือ:", userGroup);

      // fetch all quests
      let list: any[] = [];
      try {
        const res = await fetch(`${BACKEND}/quests`);
        if (res.ok) list = await res.json();
      } catch (e) {
        console.warn("fetch quests error", e);
      }

      // --- 2. กรองเฉพาะเควสที่ตรงกับกลุ่มอายุของผู้ใช้ ---
      const filteredList = list.filter((q) => {
        // ลองหา age_group จากตัว object ตรงๆ ก่อน
        let questAgeGroup = q.age_group;

        // ถ้าไม่มี ลองแกะดูใน description (กรณีที่ Admin บันทึกเป็น JSON)
        if (!questAgeGroup && q.description) {
          try {
            const parsed =
              typeof q.description === "string"
                ? JSON.parse(q.description)
                : q.description;
            questAgeGroup = parsed?.age_group || parsed?.ageGroup; // ดักเผื่อพิมพ์เล็กพิมพ์ใหญ่
          } catch (e) {
            // ไม่ใช่ JSON ข้ามไป
          }
        }

        // ถ้าเควสมีการระบุกลุ่มอายุเอาไว้ ต้องตรงกับกลุ่มอายุของ User ถึงจะแสดง
        if (questAgeGroup) {
          return questAgeGroup === userGroup;
        }

        // ถ้าเควสไม่ได้ระบุ age_group มา ให้ถือว่าเป็นเควสทั่วไป แสดงได้ปกติ
        return true;
      });

      // build candidate pools per period
      const pools: Record<PeriodKey, TaskItem[]> = {
        morning: [],
        afternoon: [],
        evening: [],
      };

      // --- 3. เอา filteredList มาวนลูปแทน list เดิม ---
      for (const q of filteredList) {
        // parse description safely
        let parsed: any = null;
        try {
          parsed =
            typeof q.description === "string"
              ? JSON.parse(q.description)
              : q.description;
        } catch {
          parsed = null;
        }

        const extract = (p: string) => {
          const arr =
            (parsed &&
              (parsed.periods || parsed.period || parsed.items) &&
              (parsed.periods?.[p] ||
                parsed.period?.[p] ||
                parsed.items?.[p])) ||
            [];
          if (!Array.isArray(arr)) return [];
          return arr.map((it: any, idx: number) => {
            const label =
              typeof it === "string"
                ? it
                : it?.text ||
                  it?.label ||
                  it?.title ||
                  q.title ||
                  `quest-${q.id}-${p}-${idx}`;
            return {
              id: it?.id ?? `${q.id}-${p}-${idx}`,
              label: String(label),
              quest_id: q.id,
              status: "pending",
              score: 0,
            } as TaskItem;
          });
        };

        const m = extract("morning");
        const a = extract("afternoon");
        const e = extract("evening");

        pools.morning.push(...m);
        pools.afternoon.push(...a);
        pools.evening.push(...e);

        // fallback: if no period items, use quest title as candidate for all periods
        if (m.length === 0 && a.length === 0 && e.length === 0 && q.title) {
          pools.morning.push({
            id: `q-${q.id}-m`,
            label: q.title,
            quest_id: q.id,
            status: "pending",
            score: 0,
          });
          pools.afternoon.push({
            id: `q-${q.id}-a`,
            label: q.title,
            quest_id: q.id,
            status: "pending",
            score: 0,
          });
          pools.evening.push({
            id: `q-${q.id}-e`,
            label: q.title,
            quest_id: q.id,
            status: "pending",
            score: 0,
          });
        }
      }

      // dedupe pools
      const uniq = (arr: TaskItem[]) => {
        const seen = new Set<string>();
        return arr.filter((it) => {
          const key = `${it.id}::${it.label}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
      };
      pools.morning = uniq(pools.morning);
      pools.afternoon = uniq(pools.afternoon);
      pools.evening = uniq(pools.evening);

      // load yesterday selection to exclude (legacy behavior kept global)
      const yesterdayRaw = await AsyncStorage.getItem(getYesterdayKey());
      let yesterdayIds = new Set<string>();
      if (yesterdayRaw) {
        try {
          const y = JSON.parse(yesterdayRaw);
          for (const p of ["morning", "afternoon", "evening"]) {
            const arr = (y[p] || []) as TaskItem[];
            for (const it of arr) {
              if (it && it.id != null) yesterdayIds.add(String(it.id));
            }
          }
        } catch {
          // ignore
        }
      }

      // sample unique items per period excluding yesterdayIds and avoiding duplicates across periods
      const sampleUnique = (pool: TaskItem[], n = 5, exclude: Set<string>) => {
        const candidates = pool.filter((it) => !exclude.has(String(it.id)));
        const out: TaskItem[] = [];
        const used = new Set<string>();
        const copy = candidates.slice();
        while (out.length < n) {
          if (copy.length === 0) {
            // if not enough unique candidates, allow using pool items not in used but may include ones excluded by yesterday
            const fallback = pool.filter((it) => !used.has(String(it.id)));
            if (fallback.length === 0) break;
            copy.push(...fallback);
          }
          const idx = Math.floor(Math.random() * copy.length);
          const item = copy.splice(idx, 1)[0];
          if (!item) break;
          const key = String(item.id);
          if (used.has(key)) continue;
          used.add(key);
          out.push({ ...item, status: "pending" });
        }
        // if still less than n, fill with placeholders
        while (out.length < n) {
          out.push({
            id: `placeholder-${Math.random().toString(36).slice(2, 9)}`,
            label: "ไม่มีรายการเพิ่มเติม",
            quest_id: null,
            status: "rejected", // placeholder treated as rejected by default
            score: 0,
          });
        }
        return out;
      };

      // ensure no overlap across periods: track usedIds across all periods
      const globalUsed = new Set<string>();
      const morningFive = sampleUnique(pools.morning, 5, yesterdayIds);
      morningFive.forEach((it) => globalUsed.add(String(it.id)));

      // for afternoon, exclude yesterday and globalUsed
      const afternoonPoolFiltered = pools.afternoon.filter(
        (it) => !globalUsed.has(String(it.id)),
      );
      const afternoonFive = sampleUnique(
        afternoonPoolFiltered.length ? afternoonPoolFiltered : pools.afternoon,
        5,
        yesterdayIds,
      );
      afternoonFive.forEach((it) => globalUsed.add(String(it.id)));

      const eveningPoolFiltered = pools.evening.filter(
        (it) => !globalUsed.has(String(it.id)),
      );
      const eveningFive = sampleUnique(
        eveningPoolFiltered.length ? eveningPoolFiltered : pools.evening,
        5,
        yesterdayIds,
      );
      eveningFive.forEach((it) => globalUsed.add(String(it.id)));

      // save today's selection (so tomorrow we can avoid them) - per user
      const todayKeyForUser = todaySelectionKeyForUser(loadedUser);
      await AsyncStorage.setItem(
        todayKeyForUser,
        JSON.stringify({
          morning: morningFive,
          afternoon: afternoonFive,
          evening: eveningFive,
        }),
      );

      // set periods
      setPeriods({
        morning: morningFive,
        afternoon: afternoonFive,
        evening: eveningFive,
      });

      // after setting selection, try to load any saved progress for this user/day and merge
      await loadProgress(loadedUser);
    } catch (e) {
      console.warn("buildDailyPeriods error", e);
      Alert.alert("ไม่สามารถโหลดเควสได้");
    } finally {
      setLoading(false);
    }
  }

  // -------------------------
  // Actions: accept / reject
  // -------------------------
  function setTaskStatus(
    periodKey: PeriodKey,
    index: number,
    status: TaskItem["status"],
  ) {
    setPeriods((prev) => {
      const copy = { ...prev };
      const arr = copy[periodKey].slice();
      if (!arr[index]) return prev;
      arr[index] = { ...arr[index], status };
      copy[periodKey] = arr;
      // save progress immediately for persistence
      saveProgress(undefined, copy).catch(() => {});
      return copy;
    });
  }

  function acceptTask(periodKey: PeriodKey, index: number) {
    if (confirmedAccept) return; // locked
    setTaskStatus(periodKey, index, "accepted");
  }
  function rejectTask(periodKey: PeriodKey, index: number) {
    if (confirmedAccept) return; // locked
    setTaskStatus(periodKey, index, "rejected");
  } // Toggle completed <-> in_progress (only after confirm)
  // -------------------------

  // -------------------------
  async function toggleComplete(periodKey: PeriodKey, index: number) {
    const item = periods[periodKey]?.[index];
    if (!item) return;
    if (!confirmedAccept) {
      Alert.alert(
        "ยังไม่ได้ยืนยันรับเควส",
        "ต้องยืนยันรับเควสก่อนจึงจะทำเสร็จได้",
      );
      return;
    } // only allowed for items that are in_progress or completed
    if (item.status === "in_progress") {
      // mark completed
      setPeriods((prev) => {
        const copy = { ...prev };
        const arr = copy[periodKey].slice();
        arr[index] = { ...arr[index], status: "completed", score: 20 };
        copy[periodKey] = arr; // persist progress
        saveProgress(undefined, copy).catch(() => {});
        return copy;
      }); // ----------------------------------------------------
      // 📌 ส่งข้อมูลไป Backend เพื่อบวกคะแนน (20) เมื่อกดทำเสร็จ
      // ----------------------------------------------------

      try {
        const token = await AsyncStorage.getItem("token");
        const headers: any = { "Content-Type": "application/json" };
        if (token) headers.Authorization = `Bearer ${token}`;
        const nowIso = new Date().toISOString();
        const payload = {
          quest_id: item.quest_id || item.id,
          items: {
            [periodKey]: [{ ...item, status: "completed", score: 20 }],
          },
          date: nowIso,
          accept_start_time: nowIso,
        };
        await fetch(`${BACKEND}/quests/progress`, {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
        });
      } catch (e) {
        console.warn("toggle sync error", e);
      }
    } else if (item.status === "completed") {
      // revert to in_progress
      setPeriods((prev) => {
        const copy = { ...prev };
        const arr = copy[periodKey].slice();
        arr[index] = { ...arr[index], status: "in_progress", score: 0 }; // 🟢 เปลี่ยนกลับเป็น 0
        copy[periodKey] = arr; // persist progress
        saveProgress(undefined, copy).catch(() => {});
        return copy;
      }); // ----------------------------------------------------
      // 📌 ส่งข้อมูลไป Backend เพื่อดึงคะแนนกลับเป็น 0 เมื่อกดยกเลิก
      // ----------------------------------------------------

      try {
        const token = await AsyncStorage.getItem("token");
        const headers: any = { "Content-Type": "application/json" };
        if (token) headers.Authorization = `Bearer ${token}`;
        const nowIso = new Date().toISOString();
        const payload = {
          quest_id: item.quest_id || item.id,
          items: {
            [periodKey]: [{ ...item, status: "in_progress", score: 0 }],
          },
          date: nowIso,
          accept_start_time: nowIso,
        };
        await fetch(`${BACKEND}/quests/progress`, {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
        });
      } catch (e) {
        console.warn("toggle sync error", e);
      }
    }
  }

  function computeTotals(p: Record<PeriodKey, TaskItem[]>) {
    let completedCount = 0;
    let totalScore = 0;
    let acceptedCount = 0;
    for (const k of Object.keys(p) as PeriodKey[]) {
      for (const it of p[k] || []) {
        if (it.status === "completed") {
          completedCount += 1;
          totalScore += Number(it.score ?? 20);
        }
        if (it.status === "accepted" || it.status === "in_progress")
          acceptedCount += 1;
      }
    }
    return { completedCount, totalScore, acceptedCount };
  } // Confirm Accept (ล็อกและตั้งรายการที่ไม่รับเป็นปฏิเสธ; accepted -> in_progress)
  // -------------------------

  // -------------------------
  async function handleConfirmAccept() {
    // ต้องมีรับอย่างน้อย 5 รายการ (รวมทุกช่วง)
    const acceptedCount = Object.keys(periods).reduce((acc, k) => {
      return (
        acc +
        (periods[k as PeriodKey] || []).filter((it) => it.status === "accepted")
          .length
      );
    }, 0);

    if (acceptedCount < 5) {
      Alert.alert(
        "เงื่อนไขไม่ครบ",
        "ต้องเลือก 'รับ' อย่างน้อย 5 รายการก่อนยืนยันรับเควส",
      );
      return;
    }

    Alert.alert(
      "ยืนยันรับเควส",
      "เมื่อรับแล้วจะไม่สามารถเปลี่ยนหรือยกเลิกเควสที่รับได้ คุณต้องการยืนยันหรือไม่?",
      [
        { text: "ยกเลิก", style: "cancel" },
        {
          text: "ยืนยัน",
          onPress: async () => {
            // lock accept set and record start time
            setConfirmedAccept(true);
            const nowIso = new Date().toISOString();
            setAcceptStartTime(nowIso); // build finalPeriods from current periods state (convert accepted -> in_progress, others -> rejected)

            const finalPeriods: Record<PeriodKey, TaskItem[]> = {
              morning: [],
              afternoon: [],
              evening: [],
            };
            for (const k of Object.keys(periods) as PeriodKey[]) {
              finalPeriods[k] = (periods[k] || []).map((it) => {
                if (it.status === "accepted") {
                  return { ...it, status: "in_progress", score: 0 };
                }
                return { ...it, status: "rejected", score: 0 };
              });
            } // update UI state with finalPeriods

            setPeriods(finalPeriods); // persist accepted state (per user) and progress

            setSaving(true);
            try {
              const key = acceptedStateKeyForUser();
              await AsyncStorage.setItem(
                key,
                JSON.stringify({
                  periods: finalPeriods,
                  acceptStartTime: nowIso,
                  confirmedAccept: true,
                }),
              ); // also save progress so completed/in_progress persist

              await saveProgress(undefined, finalPeriods); // ----------------------------------------------------
              // 📌 ส่วนที่แก้ไขใหม่ เพื่อแก้ Error 422 (จัดรูปแบบ items ให้เป็น Array)
              // ----------------------------------------------------

              const token = await AsyncStorage.getItem("token");
              const headers: any = { "Content-Type": "application/json" };
              if (token) headers.Authorization = `Bearer ${token}`;

              let hasSyncError = false; // ใช้ Object.entries เพื่อดึงชื่อช่วงเวลา (morning, afternoon, evening) ออกมาด้วย

              for (const [period, periodTasks] of Object.entries(
                finalPeriods,
              )) {
                for (const task of periodTasks) {
                  // 📌 สร้าง Payload โดยใส่ [ ] ครอบข้อมูลให้กลายเป็น Array ตามที่ Backend ต้องการ
                  const payload = {
                    quest_id: task.quest_id || task.id,
                    items: {
                      [period]: [
                        {
                          id: task.id,
                          label: task.label,
                          status: task.status,
                          quest_id: task.quest_id,
                          score: task.score,
                        },
                      ],
                    },
                    date: nowIso,
                    accept_start_time: nowIso,
                  };

                  try {
                    const res = await fetch(`${BACKEND}/quests/progress`, {
                      method: "POST",
                      headers,
                      body: JSON.stringify(payload),
                    });

                    if (!res.ok) {
                      hasSyncError = true;
                      const errorText = await res.text();
                      console.warn(
                        `Sync failed for Quest ${payload.quest_id}:`,
                        res.status,
                        errorText,
                      );
                    }
                  } catch (e) {
                    hasSyncError = true;
                    console.warn("progress sync error", e);
                  }
                }
              } // สรุปผลการซิงค์

              if (hasSyncError) {
                Alert.alert(
                  "ยืนยันแล้ว (local)",
                  "ยืนยันรับเควสเรียบร้อย แต่ซิงค์กับเซิร์ฟเวอร์ไม่สำเร็จบางรายการ",
                );
              } else {
                Alert.alert(
                  "ยืนยันและบันทึกแล้ว",
                  "ยืนยันรับเควสและบันทึกผลเรียบร้อย",
                );
              } // ----------------------------------------------------
            } catch (e) {
              console.warn("confirm accept save error", e);
              Alert.alert("เกิดข้อผิดพลาด", String(e));
            } finally {
              setSaving(false);
            }
          },
        },
      ],
    );
  }

  // -------------------------
  // Persist current selection locally (เรียกใช้เมื่อผู้ใช้ต้องการ)
  // -------------------------
  async function persistLocalState() {
    try {
      const key = todaySelectionKeyForUser();
      await AsyncStorage.setItem(key, JSON.stringify(periods));
      // also save progress explicitly
      await saveProgress();
      Alert.alert("บันทึกในเครื่องแล้ว");
    } catch (e) {
      console.warn("persistLocalState error", e);
      Alert.alert("บันทึกไม่สำเร็จ", String(e));
    }
  }

  // -------------------------
  // Clear accepted state (ล้างสถานะยืนยัน)
  // -------------------------
  async function clearAcceptedState() {
    try {
      const key = acceptedStateKeyForUser();
      await AsyncStorage.removeItem(key);
      // clear progress for today as well
      const pkey = progressKeyForUser();
      await AsyncStorage.removeItem(pkey);
      setConfirmedAccept(false);
      setAcceptStartTime(null);
      // รีเฟรชรายการใหม่
      await buildDailyPeriods();
    } catch (e) {
      console.warn("clearAcceptedState error", e);
    }
  }

  // -------------------------
  // Render
  // -------------------------
  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" />
        <Text style={{ marginTop: 8 }}>กำลังโหลดเควส...</Text>
      </View>
    );
  }

  const totals = computeTotals(periods);
  const canConfirmAccept = totals.acceptedCount >= 5 && !confirmedAccept;

  return (
    <ScrollView contentContainerStyle={styles.scrollContainer}>
      <View style={styles.container}>
        {/* 🔄 ส่วนแสดงคะแนนของผู้ใช้ และปุ่มรีเฟรช */}
        <View style={styles.headerBlock}>
          <Text style={styles.headerTitle}>เควสการนอน</Text>
          <View style={styles.scoreContainer}>
            {userProfile && (
              <View style={styles.scoreBadge}>
                <Text style={styles.scoreText}>คะแนน: {userProfile.score}</Text>
              </View>
            )}

            {/* ปุ่มรีเฟรชคะแนน */}
            <Pressable
              style={({ pressed }) => [
                styles.refreshScoreBtn,
                pressed && { opacity: 0.7 },
              ]}
              onPress={() => {
                loadUserProfile();
                fetchLeaderboard();
              }}
            >
              <Text style={styles.refreshScoreText}>🔄 รีเฟรชคะแนน</Text>
            </Pressable>
          </View>
        </View>

        {/* 🏆 ส่วนกระดานผู้นำ (Leaderboard) โชว์แค่ Top 3 */}
        <View style={styles.leaderboardSection}>
          <Text style={styles.leaderboardHeader}> คะแนนสูงสุด</Text>
          {loadingLeaderboard ? (
            <ActivityIndicator size="small" color="#007aff" />
          ) : leaderboard.length === 0 ? (
            <Text style={styles.emptyLeaderboard}>ยังไม่มีข้อมูลคะแนน</Text>
          ) : (
            leaderboard.slice(0, 3).map((item, index) => {
              const rank = index + 1;
              return (
                <View
                  key={item.user_id}
                  style={[
                    styles.leaderboardItem,
                    rank === 1 ? styles.top1 : null,
                  ]}
                >
                  <Text style={styles.rankText}>#{rank}</Text>
                  <Text style={styles.leaderboardName}>
                    {item.name || `User ${item.user_id}`}
                  </Text>
                  <Text style={styles.leaderboardScore}>
                    {item.total_score} pts
                  </Text>
                </View>
              );
            })
          )}
        </View>
        {/* ...existing code... */}
        <Text style={styles.title}>ภารกิจรายวัน</Text>
        <Text style={styles.subtitle}>
          เลือก รับ / ปฏิเสธ ให้ครบ 5 ตัวในแต่ละช่วงก่อนยืนยันรับ
        </Text>

        {(["morning", "afternoon", "evening"] as PeriodKey[]).map(
          (periodKey) => {
            const label =
              periodKey === "morning"
                ? "เช้า"
                : periodKey === "afternoon"
                  ? "บ่าย"
                  : "ค่ำ";
            const tasks = periods[periodKey] || [];
            return (
              <View key={periodKey} style={styles.periodBlock}>
                <Text style={styles.periodTitle}>{label}</Text>
                {tasks.length === 0 ? (
                  <Text style={{ color: "#666" }}>ไม่มีรายการ</Text>
                ) : (
                  tasks.map((task, idx) => (
                    <View key={`${task.id}-${idx}`} style={styles.taskRow}>
                      <View
                        style={[
                          styles.statusBox,
                          task.status === "completed"
                            ? styles.statusCompleted
                            : task.status === "in_progress"
                              ? styles.statusInProgress
                              : task.status === "accepted"
                                ? styles.statusAccepted
                                : task.status === "rejected"
                                  ? styles.statusRejected
                                  : styles.statusPending,
                        ]}
                      >
                        <Text style={styles.statusText}>
                          {task.status === "completed"
                            ? "เสร็จ"
                            : task.status === "in_progress"
                              ? "กำลังทำเควส"
                              : task.status === "accepted"
                                ? "รับแล้ว"
                                : task.status === "rejected"
                                  ? "ปฏิเสธ"
                                  : "รอดำเนินการ"}
                        </Text>
                      </View>

                      <View style={styles.taskTextWrap}>
                        <Text style={styles.taskLabel}>{task.label}</Text>
                        <Text style={styles.taskMeta}>คะแนนเมื่อเสร็จ: 20</Text>
                      </View>

                      <View style={styles.actionColumn}>
                        <Pressable
                          onPress={() => acceptTask(periodKey, idx)}
                          style={[
                            styles.actionBtn,
                            styles.acceptBtn,
                            confirmedAccept && styles.disabledBtn,
                          ]}
                          disabled={confirmedAccept}
                        >
                          <Text style={styles.actionBtnText}>รับ</Text>
                        </Pressable>

                        <Pressable
                          onPress={() => rejectTask(periodKey, idx)}
                          style={[
                            styles.actionBtn,
                            styles.rejectBtn,
                            confirmedAccept && styles.disabledBtn,
                          ]}
                          disabled={confirmedAccept}
                        >
                          <Text style={styles.actionBtnText}>ปฏิเสธ</Text>
                        </Pressable>

                        {/* ปุ่มทำเสร็จ โชว์เมื่อยืนยันรับแล้ว และล็อกให้กดได้ครั้งเดียว */}
                        {confirmedAccept &&
                          (task.status === "in_progress" ||
                            task.status === "completed") && (
                            <Pressable
                              onPress={
                                task.status === "in_progress"
                                  ? () => toggleComplete(periodKey, idx)
                                  : null
                              }
                              style={[
                                styles.actionBtn,
                                task.status === "in_progress"
                                  ? styles.completeBtn
                                  : { backgroundColor: "#bdc3c7" }, // เปลี่ยนเป็นสีเทาเมื่อสำเร็จแล้ว
                              ]}
                            >
                              <Text style={styles.actionBtnText}>
                                {task.status === "in_progress"
                                  ? "ทำเสร็จ"
                                  : "สำเร็จแล้ว"}
                              </Text>
                            </Pressable>
                          )}
                      </View>
                    </View>
                  ))
                )}
              </View>
            );
          },
        )}

        <View style={styles.footer}>
          <Text style={styles.totals}>
            รับแล้ว: {totals.acceptedCount} เสร็จแล้ว: {totals.completedCount} /
            15 คะแนนรวม: {totals.totalScore}
          </Text>
          <View style={{ height: 8 }} />

          {/* ปุ่มยืนยันรับเควส (เป็นการบันทึกด้วย) */}
          <View style={{ marginBottom: 8 }}>
            <Button
              title={
                confirmedAccept
                  ? "รับเควสแล้ว"
                  : `ยืนยันรับเควส (${totals.acceptedCount} รับ)`
              }
              onPress={handleConfirmAccept}
              disabled={!canConfirmAccept || saving}
              color={confirmedAccept ? "#6c757d" : "#007aff"}
            />
            {!canConfirmAccept && !confirmedAccept && (
              <Text style={{ color: "#666", marginTop: 6 }}>
                ต้องเลือก 'รับ' อย่างน้อย 5 รายการก่อนยืนยัน
              </Text>
            )}
            {confirmedAccept && acceptStartTime && (
              <Text style={{ color: "#28a745", marginTop: 6 }}>
                เริ่มนับเวลา: {new Date(acceptStartTime).toLocaleString()}
              </Text>
            )}
            {/* ปุ่มสำหรับดีบัก/รีเซ็ต (ถ้าต้องการ) */}
            {confirmedAccept && (
              <View style={{ marginTop: 8 }}>
                <Button
                  title="รีเซ็ตสถานะยืนยัน (ล้าง)"
                  onPress={() => {
                    Alert.alert(
                      "รีเซ็ตสถานะ",
                      "ต้องการล้างสถานะยืนยันและโหลดรายการใหม่หรือไม่?",
                      [
                        { text: "ยกเลิก", style: "cancel" },
                        {
                          text: "ล้าง",
                          style: "destructive",
                          onPress: () => clearAcceptedState(),
                        },
                      ],
                    );
                  }}
                  color="#d9534f"
                />
              </View>
            )}
          </View>
        </View>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  leaderboardSection: {
    backgroundColor: "#fff",
    borderRadius: 8,
    padding: 12,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: "#e0e0e0",
  },
  leaderboardHeader: {
    fontSize: 16,
    fontWeight: "bold",
    color: "#333",
    marginBottom: 10,
    textAlign: "center",
  },
  leaderboardItem: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    backgroundColor: "#f9f9f9",
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderRadius: 6,
    marginBottom: 6,
  },
  top1: {
    backgroundColor: "#fffbe6", // สีทองอ่อนๆ สำหรับที่ 1
    borderColor: "#ffd700",
    borderWidth: 1,
  },
  rankText: {
    fontSize: 16,
    fontWeight: "bold",
    color: "#555",
    width: 35,
  },
  leaderboardName: {
    flex: 1,
    fontSize: 14,
    color: "#333",
    fontWeight: "600",
  },
  leaderboardScore: {
    fontSize: 14,
    fontWeight: "bold",
    color: "#007aff",
  },
  emptyLeaderboard: {
    textAlign: "center",
    color: "#999",
    fontSize: 13,
    paddingVertical: 10,
  },
  scrollContainer: {
    paddingTop: 8,
    paddingBottom: 24,
    backgroundColor: "#fff",
  },
  container: { flex: 1, paddingHorizontal: 16 },
  center: { flex: 1, justifyContent: "center", alignItems: "center" },
  title: { fontSize: 20, fontWeight: "700", marginBottom: 6 },
  subtitle: { color: "#666", marginBottom: 12 },

  periodBlock: {
    marginBottom: 16,
    padding: 12,
    backgroundColor: "#fafafa",
    borderRadius: 8,
  },
  periodTitle: {
    fontSize: 16,
    fontWeight: "700",
    marginBottom: 8,
    textTransform: "capitalize",
  },

  taskRow: { flexDirection: "row", alignItems: "center", paddingVertical: 8 },
  statusBox: {
    width: 110,
    paddingVertical: 6,
    paddingHorizontal: 8,
    borderRadius: 6,
    alignItems: "center",
    justifyContent: "center",
    marginRight: 12,
  },
  statusText: { color: "#fff", fontWeight: "700", textAlign: "center" },
  statusPending: { backgroundColor: "#999" },
  statusAccepted: { backgroundColor: "#2e86de" },
  statusInProgress: { backgroundColor: "#ff9800" }, // สีสำหรับ "กำลังทำเควส"
  statusCompleted: { backgroundColor: "#28a745" },
  statusRejected: { backgroundColor: "#d9534f" },

  taskTextWrap: { flex: 1 },
  taskLabel: { fontSize: 15 },
  taskMeta: { color: "#666", marginTop: 2 },

  actionColumn: {
    width: 110,
    alignItems: "center",
    justifyContent: "flex-start",
  },
  actionBtn: {
    width: "100%",
    paddingVertical: 8,
    borderRadius: 6,
    marginTop: 6,
    alignItems: "center",
  },
  acceptBtn: { backgroundColor: "#007aff" },
  rejectBtn: { backgroundColor: "#ff4d4f" },
  completeBtn: { backgroundColor: "#28a745" },
  uncompleteBtn: { backgroundColor: "#ff9800" },
  actionBtnText: { color: "#fff", fontWeight: "700" },
  disabledBtn: { opacity: 0.5 },

  footer: {
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: "#eee",
    marginTop: 8,
  },
  totals: { fontSize: 16, fontWeight: "700", marginBottom: 6 },
  hint: { color: "#d9534f", marginTop: 8 },
  headerBlock: {
    marginBottom: 16,
    paddingHorizontal: 4,
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: "bold",
    color: "#333",
  },
  scoreContainer: {
    flexDirection: "row",
    alignItems: "center",
    marginTop: 8,
  },
  scoreBadge: {
    backgroundColor: "#e3f2fd",
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 20,
  },
  scoreText: {
    fontSize: 16,
    fontWeight: "700",
    color: "#007aff",
  },
  refreshScoreBtn: {
    marginLeft: 12,
    backgroundColor: "#f0f0f0",
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: "#ccc",
    flexDirection: "row",
    alignItems: "center",
  },
  refreshScoreText: {
    fontSize: 14,
    fontWeight: "700",
    color: "#333",
  },
});
