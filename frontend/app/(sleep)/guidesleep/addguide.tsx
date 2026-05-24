import { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';

const sleepOptions = [
  'แนะนำหลับเร็ว',
  'ตื่นนอนให้สดชื่น',
  'ท่านอนที่เหมาะสม',
  'ตัวช่วยนอนหลับ',
];

export default function AddGuideSleepScreen() {
  const [selectedOption, setSelectedOption] = useState('');
  const [note, setNote] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [sleepTime, setSleepTime] = useState('');
  const [wakeTime, setWakeTime] = useState('');
  const [token, setToken] = useState('');
  const [userId, setUserId] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    const loadAuth = async () => {
      const storedToken = await AsyncStorage.getItem('token');
      const storedUserId = await AsyncStorage.getItem('user_id');
      if (storedToken && storedUserId) {
        setToken(storedToken);
        setUserId(storedUserId);
      }
    };
    loadAuth();
  }, []);

  const handleSubmit = async () => {
    if (!selectedOption || !note || !startDate || !endDate || !sleepTime || !wakeTime) {
      Alert.alert('กรุณากรอกข้อมูลให้ครบถ้วน');
      return;
    }

    setIsSubmitting(true);
    try {
      await axios.post(
        'http://10.144.36.9:8000/guidesleep',
        {
          category: selectedOption,
          note,
          start_date: startDate,
          end_date: endDate,
          sleep_time: sleepTime,
          wake_time: wakeTime,
          user_id: userId,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      Alert.alert('เพิ่ม GuideSleep สำเร็จ');
      setSelectedOption('');
      setNote('');
      setStartDate('');
      setEndDate('');
      setSleepTime('');
      setWakeTime('');
    } catch (error) {
      console.error('โพสต์ล้มเหลว:', error);
      Alert.alert('ไม่สามารถเพิ่ม GuideSleep ได้');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.header}>เพิ่ม GuideSleep</Text>

      {sleepOptions.map((option) => (
        <TouchableOpacity
          key={option}
          style={[
            styles.optionButton,
            selectedOption === option && styles.optionSelected,
          ]}
          onPress={() => setSelectedOption(option)}
        >
          <Text
            style={[
              styles.optionText,
              selectedOption === option && styles.optionTextSelected,
            ]}
          >
            {option}
          </Text>
        </TouchableOpacity>
      ))}

      <TextInput
        style={styles.input}
        placeholder="บันทึกก่อนนอน..."
        value={note}
        onChangeText={setNote}
        multiline
      />
      <TextInput
        style={styles.input}
        placeholder="วันเริ่มบันทึก (2025-09-07)"
        value={startDate}
        onChangeText={setStartDate}
      />
      <TextInput
        style={styles.input}
        placeholder="วันไกด์ (2025-09-08)"
        value={endDate}
        onChangeText={setEndDate}
      />
      <TextInput
        style={styles.input}
        placeholder="เวลานอน (23:00)"
        value={sleepTime}
        onChangeText={setSleepTime}
      />
      <TextInput
        style={styles.input}
        placeholder="เวลาตื่น (07:00)"
        value={wakeTime}
        onChangeText={setWakeTime}
      />

      <TouchableOpacity
        style={[styles.submitButton, isSubmitting && { opacity: 0.6 }]}
        onPress={handleSubmit}
        disabled={isSubmitting}
      >
        <Text style={styles.submitText}>
          {isSubmitting ? 'กำลังบันทึก...' : 'บันทึก GuideSleep'}
        </Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20, backgroundColor: '#fff' },
  header: { fontSize: 22, fontWeight: 'bold', marginBottom: 15 },
  optionButton: {
    padding: 10,
    borderRadius: 8,
    backgroundColor: '#eee',
    marginBottom: 10,
  },
  optionSelected: {
    backgroundColor: '#007AFF',
  },
  optionText: { fontSize: 14, color: '#333' },
  optionTextSelected: { color: '#fff', fontWeight: '600' },
  input: {
    borderWidth: 1,
    borderColor: '#ccc',
    padding: 10,
    borderRadius: 8,
    marginBottom: 10,
  },
  submitButton: {
    backgroundColor: '#007AFF',
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 10,
  },
  submitText: { color: '#fff', fontSize: 16 },
});
