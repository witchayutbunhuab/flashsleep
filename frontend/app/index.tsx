// app/index.tsx
import React, { useState } from 'react';
import {
  SafeAreaView,
  View,
  StyleSheet,
  TouchableOpacity,
  Text,
  Image,
} from 'react-native';
import { DarkTheme, DefaultTheme } from '@react-navigation/native';
import { useFonts } from 'expo-font';
import { StatusBar } from 'expo-status-bar';
import { useColorScheme } from '@/hooks/useColorScheme';
import { useRouter } from 'expo-router';

import GuidesleepTabs from './(sleep)/indexx';

export default function IndexScreen() { 
  const colorScheme = useColorScheme();
  const [loaded] = useFonts({
    SpaceMono: require('../assets/fonts/SpaceMono-Regular.ttf'),
  });
  const router = useRouter();

  // ถ้าต้องการปิดการกดภายในเนื้อหา ให้ตั้งเป็น true
  // เปลี่ยนเป็น false เพื่อให้เนื้อหากดได้ตามปกติ
  const contentDisabled = true;

  const [modalVisible, setModalVisible] = useState(false);
  const [modalType, setModalType] = useState<'login' | 'register' | null>(null);

  if (!loaded) return null;

  function openModal(type: 'login' | 'register') {
    // นำทางตรงเมื่อกด (ตามที่ต้องการ)
    if (type === 'login') {
      router.replace('/login');
    } else {
      router.push('/register');
    }
  }

  function closeModal() {
    setModalVisible(false);
    setModalType(null);
  }

  return (
    // ถ้าต้องการใช้ theme ของ react-navigation ให้ห่อด้วย NavigationContainer/ThemeProvider ตามความเหมาะสม
    <View style={{ flex: 1, backgroundColor: colorScheme === 'dark' ? DarkTheme.colors.background : DefaultTheme.colors.background }}>
      <SafeAreaView style={styles.safe}>
        {/* เนื้อหา: ถ้าต้องการปิดการกด ให้ตั้ง pointerEvents="none" */}
        <View style={styles.content} pointerEvents={contentDisabled ? 'none' : 'auto'}>
          <GuidesleepTabs />
        </View>

        {/* Footer ปุ่มอยู่ด้านล่างเสมอ (ยังคงรับ touch ได้) */}
        <View style={styles.footer}>
          <TouchableOpacity
            style={[styles.btn, styles.btnPrimary]}
            onPress={() => openModal('login')}
            activeOpacity={0.8}
          >
            <Text style={styles.btnText}>เข้าสู่ระบบ</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.btn, styles.btnOutline]}
            onPress={() => openModal('register')}
            activeOpacity={0.8}
          >
            <Text style={[styles.btnText, styles.btnOutlineText]}>สมัครสมาชิก</Text>
          </TouchableOpacity>
        </View>

        <StatusBar style="auto" />
      </SafeAreaView>
    </View>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#fff' },

  /* เนื้อหา */
  content: { flex: 1 },

  /* Footer (ปรับให้เล็กลง) */
  footer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingHorizontal: 10,
    paddingVertical: 20,
    borderTopWidth: 1,
    borderTopColor: '#eee',
    backgroundColor: '#fff',
  },

  /* ปุ่ม (เล็กลง) */
  btn: {
    flex: 1,
    paddingVertical: 8,
    borderRadius: 6,
    alignItems: 'center',
    marginHorizontal: 4,
    minHeight: 36,
  },
  btnPrimary: {
    backgroundColor: '#007AFF',
  },
  btnOutline: {
    backgroundColor: '#e2ee34',
    borderWidth: 1,
    borderColor: '#e2ee34',
  },
  btnText: {
    color: '#fff',
    fontWeight: '600',
    fontSize: 14,
  },
  btnOutlineText: {
    color: '#ffffff',
  },

  /* Modal / logo styles */
  modalBackdrop: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.45)',
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 16,
  },
  modalCard: {
    width: '90%',
    maxWidth: 360,
    backgroundColor: '#fff',
    borderRadius: 10,
    padding: 16,
    alignItems: 'center',
    position: 'relative',
  },
  closeBtn: {
    position: 'absolute',
    top: 8,
    right: 8,
    padding: 6,
    zIndex: 10,
  },
  closeText: { fontSize: 16, color: '#666' },

  title: {
    fontSize: 20,
    fontWeight: '700',
    marginBottom: 8,
    color: '#333',
  },
  logo: {
    width: 88,
    height: 88,
    marginBottom: 12,
  },
  buttonWrapper: {
    width: '100%',
    alignItems: 'center',
  },
  buttonContainer: {
    marginVertical: 6,
    width: '100%',
  },
  modalAction: {
    paddingVertical: 10,
    borderRadius: 8,
    alignItems: 'center',
  },
  modalPrimary: {
    backgroundColor: '#007AFF',
  },
  modalOutline: {
    backgroundColor: '#fff',
    borderWidth: 1,
    borderColor: '#007AFF',
  },
  modalActionText: {
    color: '#fff',
    fontWeight: '600',
    fontSize: 14,
  },
  modalOutlineText: {
    color: '#007AFF',
  },
});
