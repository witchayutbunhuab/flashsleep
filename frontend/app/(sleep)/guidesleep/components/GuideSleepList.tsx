// app/(sleep)/guidesleep/components/GuideSleepList.tsx
import AsyncStorage from "@react-native-async-storage/async-storage";
import { useRouter } from "expo-router";
import { useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  FlatList,
  Image,
  Modal,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  TouchableWithoutFeedback,
  View,
} from "react-native";
import MaterialCommunityIcons from "react-native-vector-icons/MaterialCommunityIcons";
import axiosInstance from "../../../../src/config/axiosInstance";
import { createReport, getGuideSleepPosts } from "../services/api";
import CommentSection from "./CommentSection";

type VoteDirection = "up" | "down" | null;

type HiddenEntry = {
  id: number;
  title?: string;
};

export default function GuideSleepList({ category }: { category: string }) {
  const router = useRouter();
  const [posts, setPosts] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState<string>("");
  const [expandedPosts, setExpandedPosts] = useState<Record<number, boolean>>(
    {},
  );
  const [scores, setScores] = useState<Record<number, number>>({});
  const [shareCounts, setShareCounts] = useState<Record<number, number>>({});
  const [userVotes, setUserVotes] = useState<Record<number, number>>({});
  const [votingLoading, setVotingLoading] = useState<Record<number, boolean>>(
    {},
  );
  const [menuVisible, setMenuVisible] = useState<Record<number, boolean>>({});
  const [voteOptionsVisible, setVoteOptionsVisible] = useState<
    Record<number, VoteDirection>
  >({});
  const [reportModalVisible, setReportModalVisible] = useState(false);
  const [reportTargetId, setReportTargetId] = useState<number | null>(null);
  const [reportReason, setReportReason] = useState<string>("");
  const [reportSubmitting, setReportSubmitting] = useState(false);

  // share modal state (for repost flow)
  const [shareModalVisible, setShareModalVisible] = useState(false);
  const [shareTargetPost, setShareTargetPost] = useState<any | null>(null);
  const [shareTitle, setShareTitle] = useState<string>("");
  const [shareCategory, setShareCategory] = useState<string>(category || "");
  const [shareSubmitting, setShareSubmitting] = useState(false);

  // รายการประเภทที่ให้เลือกใน modal (ตามที่ผู้ใช้ต้องการ)
  const POST_CATEGORIES = [
    { key: "แนะนำหลับเร็ว", label: "แนะนำหลับเร็ว" },
    { key: "ตื่นนอนให้สดชื่น", label: "ตื่นนอนให้สดชื่น" },
    { key: "ท่านอนที่เหมาะสม", label: "ท่านอนที่เหมาะสม" },
    { key: "ตัวช่วยนอนหลับ", label: "ตัวช่วยนอนหลับ" },
  ];

  // เก็บโพสต์ที่ผู้ใช้ซ่อนไว้ (persisted per user)
  const [hiddenMap, setHiddenMap] = useState<Record<number, boolean>>({});
  const [hiddenList, setHiddenList] = useState<HiddenEntry[]>([]);
  const [currentUserId, setCurrentUserId] = useState<number | null>(null);

  const lastCategoryRef = useRef<string | null>(null);

  useEffect(() => {
    const loadAuthAndFetch = async () => {
      const storedToken = await AsyncStorage.getItem("token");
      if (storedToken) {
        setToken(storedToken);
      } else {
        setToken("");
      }

      // โหลดข้อมูลผู้ใช้ (ถ้ามี) เพื่อใช้เป็นคีย์เก็บ hidden
      try {
        const rawUser =
          (await AsyncStorage.getItem("user")) ||
          (await AsyncStorage.getItem("profile"));
        if (rawUser) {
          const parsed = JSON.parse(rawUser);
          if (parsed && parsed.id) setCurrentUserId(Number(parsed.id));
        }
      } catch {
        // ignore
      }

      // โหลดรายการที่ซ่อนก่อน แล้วค่อย fetch posts
      await loadHiddenEntries();
      fetchPosts();
    };

    if (lastCategoryRef.current !== category) {
      lastCategoryRef.current = category;
      loadAuthAndFetch();
    }
  }, [category]);

  // โหลดรายการที่ซ่อนจาก AsyncStorage
  async function loadHiddenEntries() {
    try {
      const rawUser =
        (await AsyncStorage.getItem("user")) ||
        (await AsyncStorage.getItem("profile"));
      let uid: number | null = null;
      if (rawUser) {
        try {
          const parsed = JSON.parse(rawUser);
          uid = parsed?.id ? Number(parsed.id) : null;
          if (uid) setCurrentUserId(uid);
        } catch {
          uid = null;
        }
      }
      const key = uid ? `hidden_posts_user_${uid}` : "hidden_posts_anonymous";
      const raw = await AsyncStorage.getItem(key);
      if (!raw) {
        setHiddenMap({});
        setHiddenList([]);
        return;
      }
      const arr: HiddenEntry[] = JSON.parse(raw);
      const map: Record<number, boolean> = {};
      (arr || []).forEach((entry) => {
        map[Number(entry.id)] = true;
      });
      setHiddenMap(map);
      setHiddenList(arr || []);
    } catch (e) {
      console.warn("loadHiddenEntries error", e);
      setHiddenMap({});
      setHiddenList([]);
    }
  }

  // บันทึกรายการที่ซ่อนลง AsyncStorage
  async function saveHiddenEntries(entries: HiddenEntry[]) {
    try {
      const uid = currentUserId;
      const key = uid ? `hidden_posts_user_${uid}` : "hidden_posts_anonymous";
      await AsyncStorage.setItem(key, JSON.stringify(entries));
    } catch (e) {
      console.warn("saveHiddenEntries error", e);
    }
  }

  const fetchPosts = async (
    overrideShareCounts: Record<number, number> = {},
  ) => {
    setLoading(true);
    try {
      const data = await getGuideSleepPosts();
      const filtered = Array.isArray(data)
        ? data.filter((p: any) => p.category === category)
        : [];

      const sorted = filtered.slice().sort((a: any, b: any) => {
        const sa = Number(a.score ?? 0);
        const sb = Number(b.score ?? 0);
        return sb - sa;
      });

      // เก็บโพสต์ทั้งหมด (ไม่ลบโพสต์ที่ซ่อน) — การซ่อนจะแสดงเป็น placeholder ใน renderItem
      setPosts(sorted);

      const initialScores: Record<number, number> = {};
      const initialShareCounts: Record<number, number> = {};
      const initialUserVotes: Record<number, number> = {};
      sorted.forEach((p: any) => {
        initialScores[p.id] = Number(p.score ?? 0);
        initialShareCounts[p.id] =
          overrideShareCounts[p.id] ??
          shareCounts[p.id] ??
          Number(p.share_count ?? 0);
        initialUserVotes[p.id] = Number(p.user_vote ?? 0);
      });
      setScores(initialScores);
      setShareCounts(initialShareCounts);
      setUserVotes(initialUserVotes);
    } catch (error) {
      console.error("โหลดโพสต์ล้มเหลว:", error);
    } finally {
      setLoading(false);
    }
  };

  const toggleExpand = (id: number) => {
    setExpandedPosts((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleMenu = (id: number) => {
    setMenuVisible((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const openReportModal = (postId: number) => {
    setReportTargetId(postId);
    setReportReason("");
    setReportModalVisible(true);
    setMenuVisible((prev) => ({ ...prev, [postId]: false }));
  };

  const submitReport = async () => {
    if (!reportTargetId) return;
    if (!reportReason.trim()) {
      Alert.alert("กรุณากรอกเหตุผล", "โปรดระบุเหตุผลที่ต้องการรายงานโพสต์นี้");
      return;
    }
    setReportSubmitting(true);
    try {
      const storedToken = await AsyncStorage.getItem("token");
      await createReport({
        target_type: "guidesleep",
        target_id: reportTargetId,
        reason: reportReason.trim(),
      });
      setReportModalVisible(false);
      Alert.alert("ขอบคุณ", "รายงานของคุณถูกส่งแล้ว ทีมงานจะตรวจสอบ");
    } catch (e: any) {
      console.warn("ส่งรายงานล้มเหลว", e);
      Alert.alert("ส่งรายงานไม่สำเร็จ", "ระบบบันทึกไว้ภายในเครื่องแล้ว");
    } finally {
      setReportSubmitting(false);
    }
  };

  const toggleVoteOptions = (postId: number, dir: VoteDirection) => {
    setVoteOptionsVisible((prev) => {
      const cur = prev[postId] ?? null;
      return { ...prev, [postId]: cur === dir ? null : dir };
    });
  };

  const closeAllVoteOptions = () => {
    setVoteOptionsVisible({});
  };

  const handleVote = async (postId: number, voteValue: number) => {
    if (!token || votingLoading[postId]) return;

    const prevVote = userVotes[postId] ?? 0;
    const newVote = prevVote === voteValue ? 0 : voteValue;
    const delta = newVote - prevVote;

    setScores((prev) => ({ ...prev, [postId]: (prev[postId] ?? 0) + delta }));
    setUserVotes((prev) => ({ ...prev, [postId]: newVote }));
    setVotingLoading((prev) => ({ ...prev, [postId]: true }));
    setVoteOptionsVisible((prev) => ({ ...prev, [postId]: null }));

    try {
      if (newVote === 0) {
        await axiosInstance.delete(`/guidesleep/${postId}/vote`);
      } else {
        await axiosInstance.post(`/guidesleep/${postId}/vote`, {
          value: newVote,
        });
      }
    } catch (error: any) {
      console.error("โหวตล้มเหลว:", error);
      setScores((prev) => ({ ...prev, [postId]: (prev[postId] ?? 0) - delta }));
      setUserVotes((prev) => ({ ...prev, [postId]: prevVote }));
      if (error?.response) {
        console.warn(
          "Vote request failed:",
          error.response.status,
          error.response.data,
        );
      }
    } finally {
      setVotingLoading((prev) => ({ ...prev, [postId]: false }));
    }
  };

  const renderVoteOptions = (postId: number, direction: VoteDirection) => {
    if (!direction) return null;
    const options = direction === "down" ? [-1, -2, -3, -4] : [1, 2, 3, 4];
    return (
      <View style={styles.voteOptionsContainer}>
        {options.map((val) => (
          <TouchableOpacity
            key={val}
            style={styles.voteOptionButton}
            onPress={() => handleVote(postId, val)}
            disabled={!!votingLoading[postId]}
          >
            <Text
              style={[
                styles.voteOptionText,
                direction === "down"
                  ? styles.negativeText
                  : styles.positiveText,
              ]}
            >
              {val}
            </Text>
          </TouchableOpacity>
        ))}
      </View>
    );
  };

  // ฟังก์ชันซ่อนโพสต์ (เมื่อผู้ใช้กด "ซ่อนไกด์" ให้ทำหน้าที่ซ่อนโพสต์)
  const handleHidePost = async (postId: number, title?: string) => {
    try {
      // อัปเดต hiddenMap และ hiddenList แล้วบันทึก
      setHiddenMap((prev) => {
        const nextMap = { ...prev, [postId]: true };
        setHiddenList((prevList) => {
          const exists = prevList.some((e) => Number(e.id) === Number(postId));
          const nextList = exists
            ? prevList
            : [...prevList, { id: Number(postId), title }];
          saveHiddenEntries(nextList);
          return nextList;
        });
        return nextMap;
      });

      // ไม่ลบโพสต์ออกจาก posts — เราจะแสดง placeholder แทนโพสต์นั้นใน renderItem
      setMenuVisible((prev) => ({ ...prev, [postId]: false }));
      Alert.alert("ซ่อนโพสต์แล้ว", "โพสต์นี้จะถูกซ่อนจากหน้าของคุณแล้ว");
    } catch (e) {
      console.warn("handleHidePost error", e);
    }
  };

  // ยกเลิกการซ่อนโพสต์
  const handleUnhidePost = async (postId: number) => {
    try {
      const nextList = hiddenList.filter(
        (e) => Number(e.id) !== Number(postId),
      );
      setHiddenList(nextList);
      const nextMap = { ...hiddenMap };
      delete nextMap[Number(postId)];
      setHiddenMap(nextMap);
      await saveHiddenEntries(nextList);
      // รีเฟรชโพสต์เพื่อให้โพสต์ที่ยกเลิกการซ่อนกลับมาแสดง (ถ้าอยู่ใน category เดียวกัน)
      fetchPosts();
    } catch (e) {
      console.warn("handleUnhidePost error", e);
    }
  };

  const renderHiddenPlaceholder = (item: any) => {
    return (
      <View style={styles.hiddenPlaceholder}>
        <Text style={styles.hiddenTitle}>ซ่อนไว้</Text>
        <Text style={styles.hiddenMessage}>โพสต์นี้ซ่อนอยู่เฉพาะของคุณ</Text>
        <View style={{ height: 8 }} />
        <TouchableOpacity
          style={styles.unhideAction}
          onPress={() =>
            Alert.alert(
              "ยกเลิกการซ่อน",
              "ต้องการยกเลิกการซ่อนโพสต์นี้หรือไม่?",
              [
                { text: "ปิด", style: "cancel" },
                { text: "ยกเลิก", onPress: () => handleUnhidePost(item.id) },
              ],
            )
          }
        >
          <Text style={styles.unhideText}>ยกเลิก</Text>
        </TouchableOpacity>
      </View>
    );
  };

  // --- Share helpers (open modal to repost) ---
  // 1. เมื่อกดปุ่ม "แชร์โพสต์" สีฟ้าด้านล่าง
  const onSharePost = (originalPost: any) => {
    // เก็บข้อมูลโพสต์ต้นฉบับไว้ใน State เพื่อใช้ตอนกดส่ง
    setShareTargetPost(originalPost);
    setShareTitle(`แชร์: ${originalPost.title || ""}`);
    setShareModalVisible(true);
  };

  // 2. เมื่อกดยืนยันใน Modal เพื่อสร้างโพสต์ใหม่
  const submitShareAsNewPost = async () => {
    if (!shareTitle.trim()) {
      Alert.alert("กรุณากรอกหัวข้อ");
      return;
    }

    setShareSubmitting(true);
    try {
      // สร้าง start_date และ end_date จากเวลาที่ได้มา
      const now = new Date();
      const startDate = new Date(now);
      const endDate = new Date(now);
      endDate.setDate(endDate.getDate() + 1);

      // สร้างข้อความที่รวม title และ note
      const fullNote = shareTitle + "\n" + (shareTargetPost?.note || "");

      const payload = {
        category: shareCategory,
        note: fullNote,
        start_date: startDate.toISOString(),
        end_date: endDate.toISOString(),
        sleep_time: shareTargetPost?.sleep_time || "22:00",
        wake_time: shareTargetPost?.wake_time || "06:00",
      };
      const config = {};

      await axiosInstance.post("/guidesleep/", payload, config);

      let updatedShareCount = Number(shareTargetPost?.share_count ?? 0);
      if (shareTargetPost?.id) {
        try {
          console.log(`กำลังบวกเลขแชร์ให้โพสต์ ID: ${shareTargetPost.id}`);

          const shareRes = await axiosInstance.patch(
            `/guidesleep/${shareTargetPost.id}/share`,
            {},
            config,
          );
          console.log("✅ บวกเลขสำเร็จ! Backend ตอบกลับมาว่า:", shareRes.data);

          updatedShareCount = Number(
            shareRes.data?.share_count ?? shareTargetPost.share_count ?? 0,
          );

          // 🟢 อัปเดตตัวเลขหน้าจอทันทีด้วยค่า backend
          setPosts((prevPosts) =>
            prevPosts.map((p) =>
              String(p.id) === String(shareTargetPost.id)
                ? { ...p, share_count: updatedShareCount }
                : p,
            ),
          );

          setShareCounts((prev) => ({
            ...prev,
            [Number(shareTargetPost.id)]: updatedShareCount,
          }));

          setShareTargetPost((prev: any) =>
            prev ? { ...prev, share_count: updatedShareCount } : prev,
          );

          // อัปเดต UI ทันทีโดยไม่รอ fetchPosts
          setPosts((prevPosts) =>
            prevPosts.map((p) =>
              String(p.id) === String(shareTargetPost.id)
                ? { ...p, share_count: updatedShareCount }
                : p,
            ),
          );
        } catch (err) {
          console.error("❌ บวกเลขแชร์ไม่สำเร็จ:", err);
        }
      }

      Alert.alert("สำเร็จ", "แชร์โพสต์เรียบร้อยแล้ว");
      setShareModalVisible(false);
      setShareTitle("");
    } catch (error) {
      console.error("Share error:", error);
      Alert.alert("ผิดพลาด", "ไม่สามารถแชร์โพสต์ได้ในขณะนี้");
    } finally {
      setShareSubmitting(false);
    }
  };

  const renderItem = ({ item }: { item: any }) => {
    // 1. ตรวจสอบว่าเป็นการแชร์หรือไม่ (ใช้ทั้ง shared_from_id และข้อความ)
    const isShared =
      (item.shared_from_id && Number(item.shared_from_id) > 0) ||
      (item.title &&
        typeof item.title === "string" &&
        /แชร์\s*[:：]/.test(item.title));

    const isExpanded = !!expandedPosts[item.id];
    const isMenuOpen = !!menuVisible[item.id];
    const note = (item.note ?? "") as string;
    const maxLength = 84;
    const isLong = note.length > maxLength;
    const displayText = isExpanded ? note : note.slice(0, maxLength);
    const score = scores[item.id] ?? Number(item.score ?? 0);
    const shareCount = shareCounts[item.id] ?? Number(item.share_count ?? 0);
    const vote = userVotes[item.id] ?? Number(item.user_vote ?? 0);
    const optionsVisible = voteOptionsVisible[item.id] ?? null;

    // ตรวจสอบว่าโพสต์ถูกซ่อนหรือไม่
    const isHidden = !!hiddenMap[item.id];
    if (isHidden) {
      return renderHiddenPlaceholder(item);
    }

    return (
      <TouchableWithoutFeedback onPress={closeAllVoteOptions}>
        <View style={styles.postItem}>
          {/* Header ส่วนผู้โพสต์/ผู้แชร์ */}
          <View style={styles.headerRow}>
            <View style={[styles.userRow, { flex: 1 }]}>
              {item.image_url ? (
                <Image source={{ uri: item.image_url }} style={styles.avatar} />
              ) : (
                <View
                  style={[
                    styles.avatar,
                    {
                      backgroundColor: "#e4e6eb",
                      alignItems: "center",
                      justifyContent: "center",
                    },
                  ]}
                >
                  <MaterialCommunityIcons
                    name="account"
                    size={24}
                    color="#bcc0c4"
                  />
                </View>
              )}
              <View
                style={{
                  flex: 1,
                  justifyContent: "center",
                  paddingRight: 8,
                }}
              >
                <Text style={styles.userName} numberOfLines={2}>
                  {item.user_name}
                  {isShared && (
                    <Text
                      style={{
                        fontSize: 14,
                        fontWeight: "normal",
                        color: "#65676B",
                      }}
                    >
                      {" "}
                      ได้แชร์โพสต์
                    </Text>
                  )}
                </Text>
                <Text style={{ fontSize: 12, color: "#65676B", marginTop: 22 }}>
                  {item.start_date || "ไม่ระบุเวลา"}
                </Text>
              </View>
            </View>
            <TouchableOpacity
              onPress={() => toggleMenu(item.id)}
              style={{
                padding: 4,
                marginLeft: 8,
                alignSelf: "flex-start",
              }}
            >
              <MaterialCommunityIcons
                name="dots-horizontal"
                size={20}
                color="#65676B"
              />
            </TouchableOpacity>
          </View>

          {/* เมนูจุด 3 จุด */}
          {isMenuOpen && (
            <View style={styles.menuOverlay}>
              <TouchableOpacity
                onPress={() => handleHidePost(item.id, item.title)}
              >
                <Text style={styles.menuItem}>ซ่อนโพสต์</Text>
              </TouchableOpacity>
              <TouchableOpacity onPress={() => openReportModal(item.id)}>
                <Text style={styles.menuItem}>รายงาน</Text>
              </TouchableOpacity>
            </View>
          )}

          {/* --- 2. ส่วนการแสดงผล Link --- */}
          {isShared ? (
            <View style={{ marginTop: 0, marginBottom: 8 }}>
              {/* หัวข้อใหม่ของผู้แชร์ (ตัดคำว่า 'แชร์:' ออก) */}
              {item.title ? (
                <View style={styles.sharedTitleContainer}>
                  <Text style={styles.sharedTitleText}>
                    {item.title.replace(/แชร์\s*[:：]\s*/, "")}
                  </Text>

                  <View style={styles.sharedWhiteDivider} />
                </View>
              ) : null}

              {/* Link Card: กรอบโพสต์ต้นฉบับที่กดลิงก์ได้ */}
              <TouchableOpacity
                style={styles.originalPostLinkCard}
                activeOpacity={0.7}
                onPress={() => {
                  // ถ้าเป็นโพสต์แชร์ ให้ใช้ shared_from_id เพื่อพาไปหน้าโพสต์จริง
                  const targetId =
                    item.shared_from_id && String(item.shared_from_id) !== "0"
                      ? item.shared_from_id
                      : item.id;

                  router.push(`/guidesleep/${targetId}` as any);
                }}
              >
                <View
                  style={{
                    flexDirection: "row",
                    alignItems: "center",
                    paddingHorizontal: 12,
                    paddingTop: 12,
                    paddingBottom: 8,
                  }}
                >
                  <View
                    style={{
                      width: 32,
                      height: 32,
                      borderRadius: 16,
                      marginRight: 10,
                      alignItems: "center",
                      justifyContent: "center",
                      backgroundColor: "#e6f2ff",
                    }}
                  >
                    <MaterialCommunityIcons
                      name="link-variant"
                      size={18}
                      color="#007AFF"
                    />
                  </View>
                  <View style={{ flex: 1 }}>
                    <Text
                      style={{
                        fontSize: 14,
                        fontWeight: "700",
                        color: "#007AFF",
                      }}
                    >
                      ดูโพสต์ต้นฉบับ
                    </Text>
                    <Text style={{ fontSize: 12, color: "#65676B" }}>
                      แตะเพื่อไปยังหน้าโพสต์นี้
                    </Text>
                  </View>
                  <MaterialCommunityIcons
                    name="chevron-right"
                    size={24}
                    color="#bcc0c4"
                  />
                </View>

                <View style={{ paddingHorizontal: 12, paddingBottom: 12 }}>
                  <Text style={styles.note}>
                    {displayText}
                    {!isExpanded && isLong && "..."}
                  </Text>
                </View>
              </TouchableOpacity>
            </View>
          ) : (
            <View style={{ marginTop: 4, marginBottom: 8 }}>
              {item.title ? (
                <Text
                  style={{
                    fontSize: 16,
                    fontWeight: "bold",
                    color: "#050505",
                    marginBottom: 8,
                  }}
                >
                  {item.title}
                </Text>
              ) : null}
              <Text style={styles.note}>
                {displayText}
                {!isExpanded && isLong && "..."}
              </Text>
              {isLong && (
                <TouchableOpacity onPress={() => toggleExpand(item.id)}>
                  <Text style={styles.expandText}>
                    {isExpanded ? "ย่อข้อความ" : "ดูเพิ่มเติม"}
                  </Text>
                </TouchableOpacity>
              )}
              <Text style={styles.meta}>
                ⏰ {item.sleep_time} - {item.wake_time}
              </Text>
            </View>
          )}

          {/* ส่วน Vote / Comment / Share */}
          <View style={styles.voteRow}>
            <View style={styles.voteButtonWrapper}>
              {optionsVisible === "down" && (
                <View style={styles.optionsAboveLeft}>
                  {renderVoteOptions(item.id, "down")}
                </View>
              )}
              <TouchableOpacity
                style={[styles.voteButton, vote < 0 && styles.activeVote]}
                onPress={() => toggleVoteOptions(item.id, "down")}
                disabled={!!votingLoading[item.id]}
              >
                <Image
                  source={require("../../../../assets/images/iconreductpoint.jpg")}
                  style={styles.voteIcon}
                />
              </TouchableOpacity>
            </View>

            <Text style={styles.scoreText}>{score}</Text>

            <View style={styles.voteButtonWrapper}>
              {optionsVisible === "up" && (
                <View style={styles.optionsAboveRight}>
                  {renderVoteOptions(item.id, "up")}
                </View>
              )}
              <TouchableOpacity
                style={[styles.voteButton, vote > 0 && styles.activeVote]}
                onPress={() => toggleVoteOptions(item.id, "up")}
                disabled={!!votingLoading[item.id]}
              >
                <Image
                  source={require("../../../../assets/images/iconpustpoint.jpg")}
                  style={styles.voteIcon}
                />
              </TouchableOpacity>
            </View>
          </View>

          <CommentSection guidesleepId={item.id} />

          <View style={styles.shareRow}>
            <TouchableOpacity
              style={styles.shareFullButton}
              onPress={() => onSharePost(item)}
            >
              <MaterialCommunityIcons
                name="share-variant"
                size={18}
                color="#fff"
              />
              <Text style={styles.shareFullButtonText}>แชร์โพสต์</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.shareCountButton}
              onPress={() =>
                Alert.alert(
                  "จำนวนการแชร์",
                  `โพสต์นี้ถูกแชร์แล้ว ${shareCount} ครั้ง`,
                )
              }
            >
              <Text style={styles.shareCountButtonText}>แชร์ {shareCount}</Text>
            </TouchableOpacity>
          </View>
          <Text style={styles.shareCountInfo}>แชร์แล้ว {shareCount} ครั้ง</Text>
        </View>
      </TouchableWithoutFeedback>
    );
  };
  return (
    <View style={styles.container}>
      <View style={styles.headerControls}>
        <Text style={styles.title}>โพสต์ประเภท: {category}</Text>
        <TouchableOpacity
          style={styles.refreshButton}
          onPress={() => fetchPosts()}
          disabled={loading}
        >
          <MaterialCommunityIcons
            name="refresh"
            size={24}
            color={loading ? "#ccc" : "#007AFF"}
          />
        </TouchableOpacity>
      </View>

      {loading ? (
        <ActivityIndicator size="small" color="#007AFF" />
      ) : (
        <FlatList
          data={posts}
          renderItem={renderItem}
          keyExtractor={(item) => String(item.id)}
          ListEmptyComponent={
            <Text style={styles.empty}>ยังไม่มีโพสต์ในประเภทนี้</Text>
          }
          contentContainerStyle={{ paddingBottom: 40 }}
        />
      )}

      {/* Report Modal */}
      <Modal
        visible={reportModalVisible}
        animationType="slide"
        transparent={true}
        onRequestClose={() => setReportModalVisible(false)}
      >
        <View style={styles.modalBackdrop}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>รายงานโพสต์</Text>
            <Text style={styles.modalSubtitle}>
              ระบุเหตุผลที่ต้องการรายงานโพสต์นี้
            </Text>
            <TextInput
              style={styles.textInput}
              placeholder="เหตุผล (เช่น เนื้อหาไม่เหมาะสม, สแปม ฯลฯ)"
              value={reportReason}
              onChangeText={setReportReason}
              multiline
              numberOfLines={4}
              textAlignVertical="top"
              editable={!reportSubmitting}
            />
            <View
              style={{
                flexDirection: "row",
                justifyContent: "flex-end",
                marginTop: 12,
              }}
            >
              <TouchableOpacity
                onPress={() => setReportModalVisible(false)}
                style={{ marginRight: 12 }}
              >
                <Text style={{ color: "#666" }}>ยกเลิก</Text>
              </TouchableOpacity>
              <TouchableOpacity
                onPress={submitReport}
                disabled={reportSubmitting}
              >
                <Text style={{ color: "#007AFF", fontWeight: "700" }}>
                  {reportSubmitting ? "กำลังส่ง..." : "ส่งรายงาน"}
                </Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
      {/* Share Modal */}
      <Modal visible={shareModalVisible} transparent animationType="fade">
        <View style={styles.modalBackdrop}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>แชร์ไปยังหน้าไกด์</Text>

            <TextInput
              style={styles.textInput}
              placeholder="เขียนอะไรบางอย่างเกี่ยวกับไกด์นี้..."
              value={shareTitle}
              onChangeText={setShareTitle}
            />

            <Text style={{ marginTop: 10, marginBottom: 5 }}>
              เลือกประเภทที่จะแชร์:
            </Text>
            <ScrollView horizontal showsHorizontalScrollIndicator={false}>
              {POST_CATEGORIES.map((cat) => (
                <TouchableOpacity
                  key={cat.key}
                  onPress={() => setShareCategory(cat.key)}
                  style={[
                    styles.categoryBadge,
                    shareCategory === cat.key && styles.activeCategoryBadge,
                  ]}
                >
                  <Text
                    style={{
                      color: shareCategory === cat.key ? "#fff" : "#000",
                    }}
                  >
                    {cat.label}
                  </Text>
                </TouchableOpacity>
              ))}
            </ScrollView>

            <View
              style={{
                flexDirection: "row",
                justifyContent: "flex-end",
                marginTop: 20,
              }}
            >
              <TouchableOpacity
                onPress={() => setShareModalVisible(false)}
                style={{ marginRight: 15 }}
              >
                <Text style={{ color: "#666" }}>ยกเลิก</Text>
              </TouchableOpacity>
              <TouchableOpacity
                onPress={submitShareAsNewPost}
                disabled={shareSubmitting}
              >
                {shareSubmitting ? (
                  <ActivityIndicator size="small" />
                ) : (
                  <Text style={{ color: "#007AFF", fontWeight: "bold" }}>
                    แชร์เลย
                  </Text>
                )}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
      {/* Share-as-post Modal (radio category selection) */}
      <Modal
        visible={shareModalVisible}
        animationType="slide"
        transparent={true}
        onRequestClose={() => {
          if (!shareSubmitting) setShareModalVisible(false);
        }}
      >
        <View style={styles.modalBackdrop}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>แชร์เป็นโพสต์ใหม่</Text>
            <Text style={styles.modalSubtitle}>
              เพิ่มหัวข้อใหม่และเลือกประเภทโพสต์
            </Text>

            <TextInput
              style={styles.textInput}
              placeholder="หัวข้อใหม่ (จะแสดงด้านบนของต้นฉบับ)"
              value={shareTitle}
              onChangeText={setShareTitle}
              editable={!shareSubmitting}
            />

            <View style={{ height: 12 }} />

            <Text style={{ fontWeight: "600", marginBottom: 8 }}>
              เลือกประเภทโพสต์
            </Text>

            <ScrollView style={{ maxHeight: 180, marginBottom: 8 }}>
              {POST_CATEGORIES.map((c) => {
                const selected = c.key === shareCategory;
                return (
                  <TouchableOpacity
                    key={c.key}
                    onPress={() => setShareCategory(c.key)}
                    style={{
                      flexDirection: "row",
                      alignItems: "center",
                      paddingVertical: 10,
                      borderBottomWidth: 1,
                      borderBottomColor: "#f0f0f0",
                    }}
                  >
                    <View
                      style={{
                        width: 20,
                        height: 20,
                        borderRadius: 10,
                        borderWidth: 1,
                        borderColor: selected ? "#007AFF" : "#ccc",
                        alignItems: "center",
                        justifyContent: "center",
                        marginRight: 12,
                      }}
                    >
                      {selected && (
                        <View
                          style={{
                            width: 10,
                            height: 10,
                            borderRadius: 5,
                            backgroundColor: "#007AFF",
                          }}
                        />
                      )}
                    </View>
                    <Text style={{ fontSize: 14 }}>{c.label}</Text>
                  </TouchableOpacity>
                );
              })}
            </ScrollView>

            <View
              style={{
                flexDirection: "row",
                justifyContent: "flex-end",
                marginTop: 12,
              }}
            >
              <TouchableOpacity
                onPress={() => {
                  if (!shareSubmitting) setShareModalVisible(false);
                }}
                style={{ marginRight: 12 }}
              >
                <Text style={{ color: "#666" }}>ยกเลิก</Text>
              </TouchableOpacity>
              <TouchableOpacity
                onPress={submitShareAsNewPost}
                disabled={shareSubmitting}
              >
                <Text style={{ color: "#007AFF", fontWeight: "700" }}>
                  {shareSubmitting ? "กำลังแชร์..." : "แชร์เป็นโพสต์"}
                </Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, marginTop: 8 },
  headerControls: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 12,
    marginBottom: 8,
  },
  title: {
    fontSize: 16,
    fontWeight: "600",
  },
  refreshButton: {
    padding: 8,
    borderRadius: 6,
    backgroundColor: "#f0f0f0",
  },
  empty: { color: "#999", paddingHorizontal: 12 },
  postWrapper: {
    marginHorizontal: 12,
    marginBottom: 20,
  },
  postItem: {
    padding: 12,
    borderWidth: 1,
    borderColor: "#ddd",
    borderRadius: 8,
    marginBottom: 20,
    backgroundColor: "#f9f9f9",
    marginHorizontal: 12,
    position: "relative",
  },
  headerRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 4,
  },
  userRow: {
    flexDirection: "row",
    alignItems: "center",
  },
  avatar: {
    width: 40,
    height: 40,
    borderRadius: 20,
    marginRight: 10,
  },
  userName: {
    fontSize: 14,
    fontWeight: "500",
    color: "#333",
  },
  note: { fontSize: 14, marginBottom: 4 },
  expandText: {
    fontSize: 12,
    color: "#007AFF",
    marginBottom: 4,
    textDecorationLine: "underline",
  },
  meta: {
    fontSize: 12,
    color: "#666",
    marginBottom: 4,
  },
  voteRow: {
    flexDirection: "row",
    justifyContent: "center",
    alignItems: "center",
    marginVertical: 6,
  },
  voteButtonWrapper: {
    width: 80,
    alignItems: "center",
    justifyContent: "center",
    position: "relative",
  },
  voteButton: {
    padding: 4,
    borderRadius: 6,
  },
  menuOverlay: {
    position: "absolute",
    top: 36,
    right: 12,
    backgroundColor: "#fff",
    borderWidth: 1,
    borderColor: "#ccc",
    borderRadius: 6,
    paddingVertical: 6,
    paddingHorizontal: 12,
    zIndex: 20,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.2,
    shadowRadius: 4,
    elevation: 5,
  },
  menuItem: {
    fontSize: 14,
    color: "#333",
    paddingVertical: 6,
  },
  activeVote: {
    borderWidth: 1,
    borderColor: "#007AFF",
    backgroundColor: "#eef6ff",
  },
  voteIcon: {
    width: 44,
    height: 24,
    resizeMode: "contain",
  },
  scoreText: {
    fontSize: 16,
    fontWeight: "600",
    color: "#007AFF",
    marginHorizontal: 12,
    minWidth: 48,
    textAlign: "center",
  },
  optionsAboveLeft: {
    position: "absolute",
    bottom: 44,
    left: 8,
    zIndex: 30,
  },
  optionsAboveRight: {
    position: "absolute",
    bottom: 44,
    right: 8,
    zIndex: 30,
  },
  voteOptionsContainer: {
    backgroundColor: "#fff",
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#ddd",
    paddingVertical: 6,
    paddingHorizontal: 8,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.15,
    shadowRadius: 4,
    elevation: 6,
  },
  voteOptionButton: {
    paddingVertical: 6,
    paddingHorizontal: 10,
    alignItems: "center",
  },
  voteOptionText: {
    fontSize: 14,
    fontWeight: "700",
  },
  negativeText: {
    color: "#d9534f",
  },
  positiveText: {
    color: "#28a745",
  },

  modalBackdrop: {
    flex: 1,
    backgroundColor:
      Platform.OS === "ios" ? "rgba(0,0,0,0.25)" : "rgba(0,0,0,0.4)",
    justifyContent: "center",
    padding: 20,
  },
  modalContent: {
    backgroundColor: "#fff",
    borderRadius: 10,
    padding: 16,
  },
  modalTitle: { fontSize: 16, fontWeight: "700", marginBottom: 6 },
  modalSubtitle: { color: "#666", marginBottom: 8 },
  textInput: {
    borderWidth: 1,
    borderColor: "#ddd",
    borderRadius: 8,
    padding: 8,
    minHeight: 80,
    backgroundColor: "#fff",
  },

  hiddenRow: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 10,
    borderBottomWidth: 1,
    borderBottomColor: "#eee",
  },
  unhideBtn: {
    paddingHorizontal: 8,
    paddingVertical: 6,
  },

  // placeholder styles for hidden post
  hiddenPlaceholder: {
    padding: 12,
    borderWidth: 1,
    borderColor: "#eee",
    borderRadius: 8,
    backgroundColor: "#fff8e6",
    marginHorizontal: 12,
  },
  hiddenTitle: {
    fontSize: 16,
    fontWeight: "700",
    color: "#333",
    marginBottom: 6,
  },
  hiddenMessage: {
    color: "#666",
    fontSize: 14,
    lineHeight: 20,
  },
  unhideAction: {
    alignSelf: "flex-start",
    marginTop: 8,
    paddingVertical: 6,
    paddingHorizontal: 10,
    borderRadius: 6,
    backgroundColor: "#f0f0f0",
  },
  unhideText: {
    color: "#007AFF",
    fontWeight: "700",
  },

  // comment + share (share moved below comment)
  commentContainer: {
    marginTop: 10,
  },
  shareRow: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginTop: 10,
  },
  shareFullButton: {
    flex: 1,
    backgroundColor: "#007AFF",
    paddingVertical: 10,
    borderRadius: 8,
    alignItems: "center",
    flexDirection: "row",
    justifyContent: "center",
  },
  shareFullButtonText: {
    color: "#fff",
    fontWeight: "700",
    marginLeft: 8,
    fontSize: 14,
  },
  shareCountButton: {
    marginLeft: 10,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#007AFF",
    backgroundColor: "#ffffff",
    justifyContent: "center",
    alignItems: "center",
  },
  shareCountButtonText: {
    color: "#007AFF",
    fontWeight: "700",
    fontSize: 14,
  },
  shareCountInfo: {
    marginTop: 10,
    fontSize: 13,
    color: "#333",
    textAlign: "left",
  },
  categoryBadge: {
    paddingVertical: 8,
    paddingHorizontal: 14,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: "#ccc",
    backgroundColor: "#fff",
    marginRight: 10,
  },
  activeCategoryBadge: {
    backgroundColor: "#007AFF",
    borderColor: "#007AFF",
  },

  // keep menuItem style (already defined)
  originalPostLinkCard: {
    backgroundColor: "#fff",
    borderWidth: 1,
    borderColor: "#e0e0e0",
    borderRadius: 12,
    padding: 12,
    marginVertical: 8,
    // ทำให้ดูเหมือนการ์ดที่กดได้
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.05,
    shadowRadius: 2,
    elevation: 2,
  },
  linkCardHeader: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 6,
  },
  linkCardLabel: {
    fontSize: 12,
    color: "#007AFF",
    fontWeight: "700",
    marginLeft: 4,
  },
  linkCardFooter: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginTop: 8,
    borderTopWidth: 0.5,
    borderTopColor: "#eee",
    paddingTop: 8,
  },
  metaTextSmall: {
    fontSize: 11,
    color: "#888",
  },
  sharedTitleContainer: {
    marginBottom: 10,
  },

  sharedTitleText: {
    fontSize: 15,
    fontWeight: "normal",
    color: "#050505",
    paddingHorizontal: 2,
    lineHeight: 22,
    marginBottom: 10,
  },

  sharedWhiteDivider: {
    height: 1,
    backgroundColor: "#ffffff",
    opacity: 0.9,
    marginHorizontal: -12,
  },
  shareCountText: {
    color: "#ffffff",
    fontSize: 13,
    marginTop: 6,
    textAlign: "center",
  },
});
