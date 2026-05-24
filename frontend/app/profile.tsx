import AsyncStorage from "@react-native-async-storage/async-storage";
import * as ImagePicker from "expo-image-picker";
import React, { useEffect, useState } from "react";
import {
    ActivityIndicator,
    Alert,
    FlatList,
    Image,
    KeyboardAvoidingView,
    Modal,
    Platform,
    StyleSheet,
    Text,
    TextInput,
    TouchableOpacity,
    View,
} from "react-native";
import PostEvents from "./(sleep)/guidesleep/services/postEvents";

const BACKEND_URL = "http://192.168.1.2:8000";

function EditModal({
  visible,
  initialText,
  title,
  onCancel,
  onSave,
  saving,
}: {
  visible: boolean;
  initialText?: string;
  title?: string;
  onCancel: () => void;
  onSave: (text: string) => void;
  saving?: boolean;
}) {
  const [text, setText] = useState(initialText || "");

  useEffect(() => {
    setText(initialText || "");
  }, [initialText, visible]);

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <KeyboardAvoidingView
        behavior={Platform.OS === "ios" ? "padding" : undefined}
        style={styles.modalWrapper}
      >
        <View style={styles.modalBackdrop} />
        <View style={styles.modalContainer}>
          <Text style={styles.modalTitle}>{title || "แก้ไขโพสต์"}</Text>
          <TextInput
            style={styles.modalInput}
            value={text}
            onChangeText={setText}
            placeholder="แก้ไขข้อความโพสต์..."
            multiline
          />
          <View style={styles.modalActions}>
            <TouchableOpacity
              onPress={onCancel}
              style={[styles.modalBtn, styles.modalCancel]}
            >
              <Text style={styles.modalCancelText}>ยกเลิก</Text>
            </TouchableOpacity>
            <TouchableOpacity
              onPress={() => onSave(text)}
              style={[styles.modalBtn, styles.modalSave]}
              disabled={saving}
            >
              {saving ? (
                <ActivityIndicator color="#fff" />
              ) : (
                <Text style={styles.modalSaveText}>บันทึก</Text>
              )}
            </TouchableOpacity>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

export default function ProfileScreen() {
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [gender, setGender] = useState("");
  const [birthdate, setBirthdate] = useState("");
  const [profileImage, setProfileImage] = useState<string | null>(null);
  const [userPosts, setUserPosts] = useState<any[]>([]);
  const [token, setToken] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);

  const [editModalVisible, setEditModalVisible] = useState(false);
  const [editTargetPost, setEditTargetPost] = useState<any | null>(null);
  const [savingPost, setSavingPost] = useState(false);
  const [loadingPosts, setLoadingPosts] = useState(false);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const t = await AsyncStorage.getItem("token");
        const uid = await AsyncStorage.getItem("user_id");
        setToken(t);
        setUserId(uid);
        if (!t || !uid) return;

        const res = await fetch(`${BACKEND_URL}/users/${uid}`, {
          headers: { Authorization: `Bearer ${t}` },
        });

        if (!res.ok) throw new Error("ไม่พบข้อมูล");
        const data = await res.json();
        setFirstName(data.first_name || "");
        setLastName(data.last_name || "");
        setGender(data.gender || "");
        setBirthdate(data.birthdate || "");
        setProfileImage(data.image_url || null);

        await fetchUserPosts(t, uid);
      } catch {
        Alert.alert("โหลดโปรไฟล์ไม่สำเร็จ");
      }
    };

    fetchProfile();
  }, []);

  useEffect(() => {
    const unsubUpdated = PostEvents.on(
      "postUpdated",
      ({ id, updated }: any) => {
        if (!id) return;
        setUserPosts((prev) => prev.map((p) => (p.id === id ? updated : p)));
      },
    );
    const unsubDeleted = PostEvents.on("postDeleted", ({ id }: any) => {
      if (!id) return;
      setUserPosts((prev) => prev.filter((p) => p.id !== id));
    });
    return () => {
      unsubUpdated();
      unsubDeleted();
    };
  }, []);

  const fetchUserPosts = async (t: string, uid: string) => {
    setLoadingPosts(true);
    try {
      const res = await fetch(`${BACKEND_URL}/guidesleep?user_id=${uid}`, {
        headers: { Authorization: `Bearer ${t}` },
      });
      if (!res.ok) throw new Error("failed to fetch posts");
      const data = await res.json();

      const filtered = (Array.isArray(data) ? data : []).filter(
        (p: any) => String(p.user_id) === String(uid),
      );

      setUserPosts(filtered);
    } catch {
      Alert.alert("โหลดโพสต์ไม่สำเร็จ");
    } finally {
      setLoadingPosts(false);
    }
  };

  const pickImage = async () => {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      allowsEditing: true,
      aspect: [1, 1],
      quality: 1,
    });

    if (!result.canceled) {
      const uri = result.assets[0].uri;
      await uploadImage(uri);
    }
  };

  const uploadImage = async (uri: string) => {
    if (!token || !userId) return;
    const formData = new FormData();
    formData.append("file", {
      uri,
      name: "profile.jpg",
      type: "image/jpeg",
    } as any);

    try {
      const res = await fetch(`${BACKEND_URL}/users/${userId}/upload-image`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
        body: formData,
      });

      if (!res.ok) throw new Error("Upload failed");
      const data = await res.json();
      setProfileImage(data.image_url);
    } catch {
      Alert.alert("อัปโหลดรูปภาพไม่สำเร็จ");
    }
  };

  const handleSave = async () => {
    if (!token || !userId) return;
    const payload = {
      first_name: firstName,
      last_name: lastName,
      gender,
      birthdate,
    };
    try {
      const res = await fetch(`${BACKEND_URL}/users/${userId}`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error("update failed");
      Alert.alert("บันทึกโปรไฟล์สำเร็จ");
    } catch {
      Alert.alert("เกิดข้อผิดพลาดในการบันทึก");
    }
  };

  const handleDeleteProfile = async () => {
    if (!token || !userId) return;
    Alert.alert("ยืนยันการลบ", "คุณแน่ใจหรือไม่ว่าต้องการลบโปรไฟล์นี้?", [
      { text: "ยกเลิก", style: "cancel" },
      {
        text: "ลบ",
        style: "destructive",
        onPress: async () => {
          try {
            const res = await fetch(`${BACKEND_URL}/users/${userId}`, {
              method: "DELETE",
              headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("delete failed");
            Alert.alert("ลบโปรไฟล์แล้ว");
          } catch {
            Alert.alert("เกิดข้อผิดพลาดในการลบ");
          }
        },
      },
    ]);
  };

  const openEditPost = (post: any) => {
    setEditTargetPost(post);
    setEditModalVisible(true);
  };

  const submitEditPost = async (id: number, newNote: string) => {
    if (!token || !editTargetPost) return;
    setSavingPost(true);
    try {
      // ✅ แปลง start_date / end_date ให้เป็น ISO datetime string
      const payload = {
        category: editTargetPost.category,
        note: newNote,
        start_date: new Date(editTargetPost.start_date).toISOString(),
        end_date: new Date(editTargetPost.end_date).toISOString(),
        sleep_time: editTargetPost.sleep_time,
        wake_time: editTargetPost.wake_time,
      };

      const res = await fetch(`${BACKEND_URL}/guidesleep/${id}`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error("update failed");
      const updated = await res.json();
      setUserPosts((prev) => prev.map((p) => (p.id === id ? updated : p)));
      PostEvents.emit("postUpdated", { id, updated });
      Alert.alert("แก้ไขโพสต์สำเร็จ");
    } catch {
      Alert.alert("แก้ไขโพสต์ไม่สำเร็จ");
    } finally {
      setSavingPost(false);
    }
  };

  const onSaveEditedPost = async (newText: string) => {
    if (!editTargetPost) return;
    await submitEditPost(editTargetPost.id, newText);
    setEditModalVisible(false);
    setEditTargetPost(null);
  };

  const handleDeletePost = async (id: number) => {
    if (!token) return;
    Alert.alert("ยืนยันการลบโพสต์", "คุณต้องการลบโพสต์นี้จริงหรือไม่?", [
      { text: "ยกเลิก", style: "cancel" },
      {
        text: "ลบ",
        style: "destructive",
        onPress: async () => {
          try {
            const res = await fetch(`${BACKEND_URL}/guidesleep/${id}`, {
              method: "DELETE",
              headers: { Authorization: `Bearer ${token}` },
            });
            if (res.status !== 204 && !res.ok) throw new Error("delete failed");
            setUserPosts((prev) => prev.filter((p) => p.id !== id));
            PostEvents.emit("postDeleted", { id });
            Alert.alert("ลบโพสต์สำเร็จ");
          } catch {
            Alert.alert("ลบโพสต์ไม่สำเร็จ");
          }
        },
      },
    ]);
  };

  const renderPostItem = ({ item }: { item: any }) => (
    <View style={styles.postItem}>
      <Text style={styles.postText}>{item.note}</Text>
      <Text style={styles.postSub}>เริ่มนอน: {item.sleep_time}</Text>
      <Text style={styles.postSub}>ตื่น: {item.wake_time}</Text>
      <View style={styles.postActions}>
        <TouchableOpacity
          onPress={() => openEditPost(item)}
          style={{ marginRight: 12 }}
        >
          <Text style={styles.actionText}>แก้ไข</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => handleDeletePost(item.id)}>
          <Text style={[styles.actionText, { color: "red" }]}>ลบ</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  const renderHeader = () => (
    <View>
      <Text style={styles.title}>โปรไฟล์ของคุณ</Text>

      <TouchableOpacity onPress={pickImage}>
        {profileImage ? (
          <Image source={{ uri: profileImage }} style={styles.image} />
        ) : (
          <View style={styles.imagePlaceholder}>
            <Text>เลือกรูปโปรไฟล์</Text>
          </View>
        )}
      </TouchableOpacity>

      <TextInput
        style={styles.input}
        placeholder="ชื่อ"
        value={firstName}
        onChangeText={setFirstName}
      />
      <TextInput
        style={styles.input}
        placeholder="นามสกุล"
        value={lastName}
        onChangeText={setLastName}
      />
      <TextInput
        style={styles.input}
        placeholder="เพศ"
        value={gender}
        onChangeText={setGender}
      />
      <TextInput
        style={styles.input}
        placeholder="วันเกิด (2000-12-30)"
        value={birthdate}
        onChangeText={setBirthdate}
      />

      <TouchableOpacity style={styles.button} onPress={handleSave}>
        <Text style={styles.buttonText}>บันทึก</Text>
      </TouchableOpacity>

      <TouchableOpacity
        style={[styles.button, { backgroundColor: "#FF3B30", marginTop: 10 }]}
        onPress={handleDeleteProfile}
      >
        <Text style={styles.buttonText}>ลบโปรไฟล์</Text>
      </TouchableOpacity>

      <Text style={[styles.title, { marginTop: 30 }]}>โพสต์ของคุณ</Text>
    </View>
  );

  return (
    <>
      <EditModal
        visible={editModalVisible}
        initialText={editTargetPost?.note || ""}
        title="แก้ไขโพสต์"
        onCancel={() => {
          setEditModalVisible(false);
          setEditTargetPost(null);
        }}
        onSave={onSaveEditedPost}
        saving={savingPost}
      />
      <FlatList
        data={userPosts}
        keyExtractor={(item) => String(item.id)}
        renderItem={renderPostItem}
        ListHeaderComponent={renderHeader}
        ListEmptyComponent={
          <Text style={styles.empty}>
            {loadingPosts ? "กำลังโหลด..." : "ยังไม่มีโพสต์"}
          </Text>
        }
        contentContainerStyle={{ padding: 20 }}
      />
    </>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, backgroundColor: "#fff", flex: 1 },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    marginBottom: 20,
    textAlign: "center",
  },
  input: {
    borderWidth: 1,
    borderColor: "#ccc",
    borderRadius: 8,
    padding: 10,
    marginBottom: 15,
  },
  button: { backgroundColor: "#4CAF50", padding: 15, borderRadius: 8 },
  buttonText: { color: "#fff", textAlign: "center", fontWeight: "bold" },
  image: {
    width: 120,
    height: 120,
    borderRadius: 60,
    alignSelf: "center",
    marginBottom: 20,
  },
  imagePlaceholder: {
    width: 120,
    height: 120,
    borderRadius: 60,
    backgroundColor: "#eee",
    justifyContent: "center",
    alignItems: "center",
    alignSelf: "center",
    marginBottom: 20,
  },
  postItem: {
    padding: 12,
    borderWidth: 1,
    borderColor: "#ddd",
    borderRadius: 8,
    marginBottom: 12,
    backgroundColor: "#f9f9f9",
  },
  postText: { fontSize: 14, marginBottom: 6 },
  postSub: { fontSize: 12, color: "#666" },
  postActions: { flexDirection: "row", marginTop: 6 },
  actionText: { fontSize: 12, color: "#007AFF" },
  empty: {
    textAlign: "center",
    color: "#999",
    fontStyle: "italic",
    marginTop: 10,
  },

  modalWrapper: { flex: 1, justifyContent: "center", alignItems: "center" },
  modalBackdrop: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: "#00000066",
  },
  modalContainer: {
    width: "92%",
    maxHeight: "80%",
    backgroundColor: "#fff",
    borderRadius: 10,
    padding: 16,
    elevation: 6,
  },
  modalTitle: { fontSize: 16, fontWeight: "600", marginBottom: 8 },
  modalInput: {
    minHeight: 80,
    maxHeight: 300,
    borderWidth: 1,
    borderColor: "#ddd",
    borderRadius: 8,
    padding: 10,
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
  modalCancel: { backgroundColor: "#eee" },
  modalSave: { backgroundColor: "#007AFF" },
  modalCancelText: { color: "#333" },
  modalSaveText: { color: "#fff", fontWeight: "600" },
});
