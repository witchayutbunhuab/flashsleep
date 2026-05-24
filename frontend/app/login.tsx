import AsyncStorage from "@react-native-async-storage/async-storage";
import { useRouter } from "expo-router";
import React, { useState } from "react";
import {
    Alert,
    StyleSheet,
    Text,
    TextInput,
    TouchableOpacity,
    View,
} from "react-native";

const BACKEND_URL = "http://192.168.1.2:8000";

export default function LoginScreen() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleLogin = async () => {
    if (!email || !password) {
      Alert.alert("กรุณากรอกอีเมลและรหัสผ่าน");
      return;
    }

    try {
      const response = await fetch(`${BACKEND_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || "อีเมลหรือรหัสผ่านไม่ถูกต้อง");
      }

      const data = await response.json();
      const token = data.token;
      const userObj = data.user;
      const userId = userObj?.id;

      // Save token, user_id and full user object (so client can read role, image_url, etc.)
      await AsyncStorage.setItem("token", token);
      if (userId !== undefined && userId !== null) {
        await AsyncStorage.setItem("user_id", userId.toString());
      }
      if (userObj) {
        try {
          await AsyncStorage.setItem("user", JSON.stringify(userObj));
        } catch (e) {
          console.warn("Failed to cache user object", e);
        }
      }

      Alert.alert("เข้าสู่ระบบสำเร็จ");
      router.replace("/(sleep)/indexx");
    } catch (error: any) {
      console.error("Login error:", error);
      Alert.alert("เข้าสู่ระบบล้มเหลว", error.message || "เกิดข้อผิดพลาด");
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>เข้าสู่ระบบ</Text>

      <TextInput
        style={styles.input}
        placeholder="อีเมล"
        value={email}
        onChangeText={setEmail}
        autoCapitalize="none"
        keyboardType="email-address"
      />

      <TextInput
        style={styles.input}
        placeholder="รหัสผ่าน"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
      />

      <TouchableOpacity style={styles.loginButton} onPress={handleLogin}>
        <Text style={styles.loginButtonText}>ล็อกอิน</Text>
      </TouchableOpacity>

      <TouchableOpacity onPress={() => router.push("/register")}>
        <Text style={styles.registerText}>ยังไม่มีบัญชี สมัครสมาชิก</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    padding: 20,
  },
  title: { fontSize: 24, marginBottom: 20 },
  input: {
    width: "100%",
    height: 40,
    borderWidth: 1,
    borderColor: "#ccc",
    paddingHorizontal: 10,
    borderRadius: 5,
    marginBottom: 15,
  },
  loginButton: {
    backgroundColor: "green",
    padding: 10,
    width: "100%",
    alignItems: "center",
    borderRadius: 5,
    marginBottom: 10,
  },
  loginButtonText: { color: "#fff", fontSize: 16 },
  registerText: { color: "blue", marginTop: 10 },
});
