// app\(sleep)\indexx.tsx
import { createMaterialTopTabNavigator } from '@react-navigation/material-top-tabs';
import React, { Suspense, lazy } from 'react';
import { ActivityIndicator } from 'react-native';

const Tab = createMaterialTopTabNavigator();

// Lazy load แต่ละหน้า
const GuidesleepScreen = lazy(() => import('./guidesleep/guidesleep'));
const DiarysleepScreen = lazy(() => import('./guidesleep/diarysleep'));
const QuestsleepScreen = lazy(() => import('./guidesleep/questsleep'));


const categories = [
  { key: 'guidesleep', title: 'Guidesleep', component: GuidesleepScreen },
  { key: 'diarysleep', title: 'Diarysleep', component: DiarysleepScreen },
  { key: 'questsleep', title: 'Questsleep', component: QuestsleepScreen },
];

export default function GuidesleepTabs() {
  return (
    <Tab.Navigator
      screenOptions={{
        tabBarIndicatorStyle: { backgroundColor: '#007AFF' },
        tabBarLabelStyle: { fontSize: 14, fontWeight: '600' },
        tabBarStyle: { backgroundColor: '#fff' },
      }}
    >
      {categories.map(({ key, title, component: Component }) => (
        <Tab.Screen
          key={key}
          name={title}
          children={() => (
            <Suspense fallback={<ActivityIndicator size="large" />}>
              <Component />
            </Suspense>
          )}
          options={{ title }}
        />
      ))}
    </Tab.Navigator>
  );
}
