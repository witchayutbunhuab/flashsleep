// app/(sleep)/_layout.tsx
import AsyncStorage from "@react-native-async-storage/async-storage";
import { Buffer } from "buffer";
import { Slot, useRouter } from "expo-router";
import React, { useEffect, useState } from "react";
import {
    ActivityIndicator,
    Image,
    StyleSheet,
    Text,
    TouchableOpacity,
    View,
} from "react-native";

const BACKEND_URL = "http://192.168.1.2:8000"; // emulator

function parseJwtPayload(token: string | null): any | null {
  if (!token) return null;
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payload = parts[1];
    // base64url -> base64
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const decoded = Buffer.from(padded, "base64").toString("utf8");
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

export default function SleepLayout() {
  const router = useRouter();
  const [profileImageUrl, setProfileImageUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    let mounted = true;

    const fetchProfileAndRole = async () => {
      try {
        const token = await AsyncStorage.getItem("token");
        const userId = await AsyncStorage.getItem("user_id");

        // Try cached user first
        const cachedUser = await AsyncStorage.getItem("user");
        if (cachedUser) {
          try {
            const u = JSON.parse(cachedUser);
            // debug logs (visible in Metro / RN debugger)
            console.log("SleepLayout: cached user:", u);
            if (mounted)
              setIsAdmin(u?.role === "admin" || u?.role === "superadmin");
            if (mounted && u?.image_url) setProfileImageUrl(u.image_url);
          } catch (e) {
            console.warn("SleepLayout: failed to parse cached user", e);
          }
        }

        // If token contains role claim, use it (fast)
        if (token) {
          const payload = parseJwtPayload(token);
          console.log("SleepLayout: token payload:", payload);
          if (payload && payload.role) {
            if (mounted)
              setIsAdmin(
                payload.role === "admin" || payload.role === "superadmin",
              );
          }
        }

        if (!token || !userId) {
          if (mounted) setLoading(false);
          return;
        }

        // Fetch fresh profile from server to keep role in sync
        const res = await fetch(`${BACKEND_URL}/users/${userId}`, {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });

        if (!res.ok) {
          console.warn("SleepLayout: /users fetch failed", res.status);
          if (mounted) setLoading(false);
          return;
        }

        const data = await res.json();
        console.log("SleepLayout: /users response:", data);

        if (mounted) {
          setProfileImageUrl(
            data.image_url || (data.user && data.user.image_url) || null,
          );
          const role = data.role || (data.user && data.user.role) || null;
          console.log("SleepLayout: resolved role:", role);
          setIsAdmin(role === "admin" || role === "superadmin");
        }

        // merge and cache user object for faster next load
        try {
          const existing = cachedUser ? JSON.parse(cachedUser) : {};
          // normalize shape: if server returned top-level user object, merge accordingly
          const serverUser = data.user ? data.user : data;
          const merged = { ...existing, ...serverUser };
          await AsyncStorage.setItem("user", JSON.stringify(merged));
        } catch (e) {
          console.warn("SleepLayout: failed to cache merged user", e);
        }
      } catch (e) {
        console.warn("SleepLayout: unexpected error fetching profile/role", e);
        if (mounted) {
          setProfileImageUrl(null);
          setIsAdmin(false);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchProfileAndRole();

    return () => {
      mounted = false;
    };
  }, []);

  const onPressProfile = () => {
    router.push("/profile");
  };

  const onPressAdmin = () => {
    router.push("/(admin)/homeadmin");
  };

  return (
    <View style={{ flex: 1 }}>
      {/* Header */}
      <View style={styles.header}>
        <View style={styles.leftGroup}>
          <TouchableOpacity
            onPress={onPressProfile}
            style={styles.profileTouch}
          >
            {loading ? (
              <ActivityIndicator size="small" />
            ) : profileImageUrl ? (
              <Image
                source={{ uri: profileImageUrl }}
                style={styles.profileIcon}
              />
            ) : (
              <View style={styles.profilePlaceholder}>
                <Image
                  source={require("../../assets/images/icon.png")}
                  style={styles.profileIcon}
                />
              </View>
            )}
          </TouchableOpacity>
        </View>

        <Image
          source={require("../../assets/images/logo_flashsleep.png")}
          style={styles.logo}
          resizeMode="contain"
        />

        {/* Right group: admin button placed at same vertical level as logo/profile */}
        <View style={styles.rightGroup}>
          {isAdmin ? (
            <TouchableOpacity onPress={onPressAdmin} style={styles.adminButton}>
              <Text style={styles.adminButtonText}>Admin</Text>
            </TouchableOpacity>
          ) : (
            // keep spacing consistent when admin button not shown
            <View style={{ width: 60 }} />
          )}
        </View>
      </View>

      {/* Content */}
      <Slot />
    </View>
  );
}

const styles = StyleSheet.create({
  header: {
    height: 60,
    backgroundColor: "#fff",
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 10,
    borderBottomWidth: 1,
    borderBottomColor: "#eee",
  },
  leftGroup: {
    flexDirection: "row",
    alignItems: "center",
    minWidth: 60,
  },
  rightGroup: {
    flexDirection: "row",
    alignItems: "center",
    minWidth: 60,
    justifyContent: "flex-end",
  },
  profileTouch: {
    marginRight: 8,
  },
  profileIcon: {
    width: 30,
    height: 30,
    borderRadius: 15,
  },
  profilePlaceholder: {
    width: 30,
    height: 30,
    borderRadius: 15,
    backgroundColor: "#eee",
    justifyContent: "center",
    alignItems: "center",
  },
  adminButton: {
    backgroundColor: "#ff4d4f",
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 6,
    justifyContent: "center",
    alignItems: "center",
  },
  adminButtonText: {
    color: "#fff",
    fontSize: 13,
    fontWeight: "700",
  },
  logo: {
    width: 140,
    height: 40,
  },
});
