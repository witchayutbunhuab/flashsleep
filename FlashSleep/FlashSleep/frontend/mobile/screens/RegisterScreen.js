import React, { useState } from 'react';
import { View, TextInput, Button, Alert } from 'react-native';

export default function RegisterScreen() {
  const [form, setForm] = useState({
    first_name: '',
    last_name: '',
    gender: '',
    birthdate: '',
    email: '',
    password: '',
    confirm_password: ''
  });

  const handleRegister = () => {
    fetch("http://127.0.0.1:8000/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    })
      .then(res => res.json())
      .then(data => Alert.alert("Result", data.message))
      .catch(err => console.log(err));
  };

  return (
    <View>
      <TextInput placeholder="First Name" onChangeText={(val) => setForm({ ...form, first_name: val })} />
      <TextInput placeholder="Last Name" onChangeText={(val) => setForm({ ...form, last_name: val })} />
      <TextInput placeholder="Gender" onChangeText={(val) => setForm({ ...form, gender: val })} />
      <TextInput placeholder="Birthdate (YYYY-MM-DD)" onChangeText={(val) => setForm({ ...form, birthdate: val })} />
      <TextInput placeholder="Email" onChangeText={(val) => setForm({ ...form, email: val })} />
      <TextInput placeholder="Password" secureTextEntry onChangeText={(val) => setForm({ ...form, password: val })} />
      <TextInput placeholder="Confirm Password" secureTextEntry onChangeText={(val) => setForm({ ...form, confirm_password: val })} />
      <Button title="Register" onPress={handleRegister} />
    </View>
  );
}
