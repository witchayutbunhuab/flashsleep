// // app/(admin)/_layout.tsx
// import React, { useEffect, useState } from "react";
// import { View, ActivityIndicator, Alert } from "react-native";
// import { Slot, useRouter } from "expo-router";
// // Adjust import path if your project layout differs.
// // This assumes auth helper is at app/src/lib/auth.ts and compiled path resolves to ../../src/lib/auth
// import { isAdmin, getToken } from "../src/lib/auth";

// export default function AdminLayout() {
//   const router = useRouter();
//   const [loading, setLoading] = useState(true);

//   useEffect(() => {
//     (async () => {
//       try {
//         const token = await getToken();
//         if (!token) {
//           router.replace("/login");
//           return;
//         }
//         const ok = await isAdmin();
//         if (!ok) {
//           Alert.alert("ไม่มีสิทธิ์", "บัญชีของคุณไม่มีสิทธิ์เข้าถึงส่วนแอดมิน");
//           router.replace("/");
//           return;
//         }
//       } catch (e) {
//         // on unexpected error, redirect to home
//         router.replace("/");
//       } finally {
//         setLoading(false);
//       }
//     })();
//   }, []);

//   if (loading) {
//     return (
//       <View style={{ flex: 1, justifyContent: "center", alignItems: "center" }}>
//         <ActivityIndicator />
//       </View>
//     );
//   }
//   return <Slot />;
// }
