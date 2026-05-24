import AsyncStorage from "@react-native-async-storage/async-storage";
import axios from "axios";
import { useEffect, useState } from "react";
import {
    Alert,
    FlatList,
    Image,
    StyleSheet,
    Text,
    TextInput,
    TouchableOpacity,
    View,
} from "react-native";

export default function CommentSection({
  guidesleepId,
}: {
  guidesleepId: number;
}) {
  const [comments, setComments] = useState([]);
  const [content, setContent] = useState("");
  const [token, setToken] = useState("");
  const [userId, setUserId] = useState("");
  const [loading, setLoading] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [expandedComments, setExpandedComments] = useState<
    Record<number, boolean>
  >({});

  useEffect(() => {
    const load = async () => {
      const t = await AsyncStorage.getItem("token");
      const uid = await AsyncStorage.getItem("user_id");
      if (t && uid) {
        setToken(t);
        setUserId(uid);
        fetchComments(t);
      }
    };
    load();
  }, [guidesleepId]);

  const fetchComments = async (authToken: string) => {
    setLoading(true);
    try {
      const res = await axios.get(
        `http://192.168.1.2:8000/comments/${guidesleepId}`,
        {
          headers: { Authorization: `Bearer ${authToken}` },
        },
      );
      setComments(res.data);
    } catch (error) {
      console.error("โหลดความคิดเห็นล้มเหลว:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async () => {
    if (!content.trim()) return;
    try {
      if (editingId) {
        await axios.put(
          `http://192.168.1.2:8000/comments/${editingId}`,
          { content, guidesleep_id: guidesleepId },
          { headers: { Authorization: `Bearer ${token}` } },
        );
        setEditingId(null);
      } else {
        await axios.post(
          "http://192.168.1.2:8000/comments",
          { content, guidesleep_id: guidesleepId },
          { headers: { Authorization: `Bearer ${token}` } },
        );
      }
      setContent("");
      fetchComments(token);
    } catch (error) {
      console.error("ส่งความคิดเห็นล้มเหลว:", error);
    }
  };

  const handleEdit = (commentId: number, currentContent: string) => {
    setEditingId(commentId);
    setContent(currentContent);
  };

  const handleDelete = async (commentId: number) => {
    Alert.alert("ยืนยันการลบ", "คุณต้องการลบความคิดเห็นนี้ใช่หรือไม่?", [
      { text: "ยกเลิก", style: "cancel" },
      {
        text: "ลบ",
        style: "destructive",
        onPress: async () => {
          try {
            await axios.delete(
              `http://192.168.1.2:8000/comments/${commentId}`,
              {
                headers: { Authorization: `Bearer ${token}` },
              },
            );
            fetchComments(token);
          } catch (error) {
            console.error("ลบความคิดเห็นล้มเหลว:", error);
          }
        },
      },
    ]);
  };

  const toggleCommentExpand = (id: number) => {
    setExpandedComments((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const renderItem = ({ item }: { item: any }) => {
    const isExpanded = expandedComments[item.id];
    const maxLength = 120;
    const isLong = item.content.length > maxLength;
    const displayText = isExpanded
      ? item.content
      : item.content.slice(0, maxLength);

    return (
      <View style={styles.commentItem}>
        {item.image_url && (
          <Image source={{ uri: item.image_url }} style={styles.avatar} />
        )}
        <View style={styles.commentText}>
          <Text style={styles.userName}>{item.user_name}</Text>
          <Text>
            {displayText}
            {!isExpanded && isLong && "..."}
          </Text>
          {isLong && (
            <TouchableOpacity onPress={() => toggleCommentExpand(item.id)}>
              <Text style={styles.expandText}>
                {isExpanded ? "ย่อข้อความ" : "ดูเพิ่มเติม"}
              </Text>
            </TouchableOpacity>
          )}
          {item.user_id.toString() === userId && (
            <View style={styles.actions}>
              <TouchableOpacity
                onPress={() => handleEdit(item.id, item.content)}
              >
                <Text style={styles.actionText}>แก้ไข</Text>
              </TouchableOpacity>
              <TouchableOpacity onPress={() => handleDelete(item.id)}>
                <Text style={[styles.actionText, { color: "red" }]}>ลบ</Text>
              </TouchableOpacity>
            </View>
          )}
        </View>
      </View>
    );
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>ความคิดเห็น</Text>
      <FlatList
        data={comments}
        keyExtractor={(item) => item.id.toString()}
        renderItem={renderItem}
        scrollEnabled={false}
        ListEmptyComponent={
          !loading && <Text style={styles.empty}>ยังไม่มีความคิดเห็น</Text>
        }
      />
      <TextInput
        style={styles.input}
        placeholder="แสดงความคิดเห็น..."
        value={content}
        onChangeText={setContent}
      />
      <TouchableOpacity style={styles.button} onPress={handleSubmit}>
        <Text style={styles.buttonText}>
          {editingId ? "บันทึกการแก้ไข" : "ส่งความคิดเห็น"}
        </Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { marginTop: 20 },
  title: { fontSize: 16, fontWeight: "600", marginBottom: 10 },
  empty: { color: "#999", fontStyle: "italic", marginBottom: 10 },
  commentItem: { flexDirection: "row", marginBottom: 10 },
  avatar: { width: 40, height: 40, borderRadius: 20, marginRight: 10 },
  commentText: { flex: 1 },
  userName: { fontWeight: "500", marginBottom: 2 },
  actions: { flexDirection: "row", marginTop: 4, gap: 12 },
  actionText: { fontSize: 12, color: "#007AFF" },
  expandText: {
    fontSize: 12,
    color: "#007AFF",
    marginTop: 4,
    textDecorationLine: "underline",
  },
  input: {
    borderWidth: 1,
    borderColor: "#ccc",
    padding: 10,
    borderRadius: 8,
    marginTop: 10,
  },
  button: {
    backgroundColor: "#007AFF",
    padding: 10,
    borderRadius: 8,
    marginTop: 10,
    alignItems: "center",
  },
  buttonText: { color: "#fff", fontWeight: "600" },
});
