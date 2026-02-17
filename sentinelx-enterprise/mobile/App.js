import React, { useEffect, useState } from "react";
import { SafeAreaView, ScrollView, Text, View, StyleSheet } from "react-native";

export default function App() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/2");
    ws.onopen = () => ws.send("mobile-subscribe");
    ws.onmessage = (event) => setAlerts((prev) => [JSON.parse(event.data), ...prev]);
    return () => ws.close();
  }, []);

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>SENTINEL-X Mobile SOC</Text>
      <ScrollView>
        {alerts.map((a, i) => (
          <View key={i} style={styles.alertCard}>
            <Text style={styles.level}>{a.severity?.toUpperCase?.() || "INFO"}</Text>
            <Text style={styles.message}>{a.message}</Text>
          </View>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#040812", padding: 20 },
  title: { color: "#8fd9ff", fontSize: 22, fontWeight: "700", marginBottom: 16 },
  alertCard: { backgroundColor: "#0f1a33", borderRadius: 12, padding: 12, marginBottom: 10 },
  level: { color: "#51e5ff", fontWeight: "700", marginBottom: 8 },
  message: { color: "#d8e9ff" },
});
