// app/_layout.tsx
import * as React from 'react';
// 1. เปลี่ยนจาก NavigationContainer เป็น ThemeProvider
import { DarkTheme, DefaultTheme, ThemeProvider } from '@react-navigation/native'; 
import { useFonts } from 'expo-font';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import 'react-native-reanimated';

import { useColorScheme } from '@/hooks/useColorScheme';

export default function RootLayout() {
  const colorScheme = useColorScheme();
  const [loaded] = useFonts({
    SpaceMono: require('../assets/fonts/SpaceMono-Regular.ttf'),
  });

  if (!loaded) {
    return null;
  }

  const theme = colorScheme === 'dark' ? DarkTheme : DefaultTheme;

  return (
    // 2. ใช้ ThemeProvider และเปลี่ยน props จาก theme={...} เป็น value={...}
    <ThemeProvider value={theme}> 
      <Stack initialRouteName="index">
        <Stack.Screen name="index" options={{ headerShown: false }} />
        <Stack.Screen name="login" options={{ headerShown: false }} />
        <Stack.Screen name="register" options={{ title: 'สมัครสมาชิก' }} />
        <Stack.Screen name="guidesleep" options={{ title: 'guidesleep' }} />
        <Stack.Screen name="+not-found" />
      </Stack>
      <StatusBar style="auto" />
    </ThemeProvider>
  );
}
