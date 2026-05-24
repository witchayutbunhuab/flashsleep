// // app/components/AuthBanner.tsx
// import React from 'react';
// import { View, Text, StyleSheet, TouchableOpacity, Animated } from 'react-native';
// import AsyncStorage from '@react-native-async-storage/async-storage';
// import { useRouter, useFocusEffect } from 'expo-router';

// export default function AuthBanner() {
//   const router = useRouter();
//   const anim = React.useRef(new Animated.Value(0)).current;
//   const [visible, setVisible] = React.useState(false);

//   const checkToken = async () => {
//     try {
//       const token = await AsyncStorage.getItem('token');
//       if (!token) {
//         setVisible(true);
//         Animated.timing(anim, { toValue: 1, duration: 220, useNativeDriver: true }).start();
//       } else {
//         Animated.timing(anim, { toValue: 0, duration: 180, useNativeDriver: true }).start(() => setVisible(false));
//       }
//     } catch {
//       setVisible(true);
//     }
//   };

//   React.useEffect(() => { checkToken(); }, []);
//   useFocusEffect(React.useCallback(() => { checkToken(); }, []));

//   if (!visible) return null;

//   /**
//    * IMPORTANT:
//    * - We set pointerEvents="box-none" on the outer Animated.View so the banner
//    *   does not block touches to the underlying guidesleep list or other UI.
//    * - The inner buttons keep pointerEvents default (they are touchable).
//    * - This allows unauthenticated users to still scroll and interact with guidesleep,
//    *   while showing a non-blocking banner prompting them to register/login.
//    */
//   return (
//     <Animated.View
//       pointerEvents="box-none"
//       style={[
//         styles.containerWrapper,
//         { transform: [{ translateY: anim.interpolate({ inputRange: [0,1], outputRange: [80,0] }) }] }
//       ]}
//     >
//       <View style={styles.container} pointerEvents="auto">
//         <Text style={styles.text}>ลงทะเบียนก่อนหากยังไม่มีบัญชีเข้าใช้งาน FlashSleep</Text>
//         <View style={styles.buttons}>
//           <TouchableOpacity style={[styles.btn, styles.register]} onPress={() => router.push('/register')}>
//             <Text style={styles.btnText}>สมัครสมาชิก</Text>
//           </TouchableOpacity>
//           <TouchableOpacity style={[styles.btn, styles.login]} onPress={() => router.push('/login')}>
//             <Text style={styles.btnText}>เข้าสู่ระบบ</Text>
//           </TouchableOpacity>
//         </View>
//       </View>
//     </Animated.View>
//   );
// }

// const styles = StyleSheet.create({
//   // wrapper is full-width but does not intercept touches (pointerEvents="box-none")
//   containerWrapper: {
//     position: 'absolute',
//     left: 12,
//     right: 12,
//     bottom: 18,
//     alignItems: 'center',
//   },
//   // actual visible banner (this view receives touches)
//   container: {
//     backgroundColor: '#fff',
//     borderRadius: 12,
//     padding: 12,
//     shadowColor: '#000',
//     shadowOpacity: 0.12,
//     shadowOffset: { width: 0, height: 4 },
//     shadowRadius: 8,
//     elevation: 8,
//     alignItems: 'center',
//     minWidth: 200,
//   },
//   text: { color: '#333', marginBottom: 8, textAlign: 'center', fontSize: 14 },
//   buttons: { flexDirection: 'row' },
//   btn: { paddingVertical: 8, paddingHorizontal: 14, borderRadius: 8, marginHorizontal: 6 },
//   register: { backgroundColor: '#FFD54F' },
//   login: { backgroundColor: '#007AFF' },
//   btnText: { color: '#fff', fontWeight: '600' },
// });
