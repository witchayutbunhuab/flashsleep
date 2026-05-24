// app/(sleep)/guidesleep/posture.tsx
import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import AddGuideSleepForm from './components/AddGuideSleepForm';
import GuideSleepList from './components/GuideSleepList';

export default function PostureScreen() {
  const category = 'ท่านอนที่เหมาะสม';

  return (
    <View style={styles.container}>
      <Text style={styles.header}>โพสต์: {category}</Text>
      <AddGuideSleepForm defaultCategory={category} />
      <GuideSleepList category={category} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#fff',
  },
  header: {
    fontSize: 20,
    fontWeight: '600',
    marginBottom: 12,
    color: '#333',
  },
});
