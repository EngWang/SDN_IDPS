# 🛡️ DDoS Detection in SDN using XGBoost

This project applies machine learning (XGBoost) to detect and respond to DDoS attacks in **Software-Defined Networking (SDN)** using **Ryu controller** and **Mininet**.

## 📁 Project Structure

```
.
├── dataset_sdn.csv               # Dataset dùng để huấn luyện
├── train_ddos_xgboost.py         # Huấn luyện mô hình XGBoost
├── xgboost_ddos_model.pkl        # Mô hình đã huấn luyện
├── scaler.pkl                    # Đối tượng chuẩn hóa (StandardScaler)
├── ryu_ddos_controller.py        # Ryu controller phát hiện DDoS
├── confusion_matrix.png          # Hình ảnh ma trận nhầm lẫn
├── feature_importance.png        # Hình ảnh biểu đồ quan trọng đặc trưng
└── README.md
```

## 🧠 Mô tả

- **XGBoost model** được huấn luyện trên tập dữ liệu SDN bao gồm 23 đặc trưng từ các luồng mạng.
- **Ryu controller** được tích hợp sẵn mô hình và scaler để dự đoán theo thời gian thực.
- Tấn công có thể được thực hiện trực tiếp qua terminal (ví dụ: `ping -f`, `hping3`, v.v.)

## ⚙️ Cài đặt

### 1. Cài môi trường
```bash
sudo apt update
sudo apt install python3-pip
pip3 install pandas scikit-learn xgboost matplotlib seaborn joblib
```

### 2. Cài Mininet và Ryu (nếu chưa có)
```bash
sudo apt install mininet
pip3 install ryu
```

## 🚀 Huấn luyện mô hình
```bash
python3 train_ddos_xgboost.py
```

> Output: `xgboost_ddos_model.pkl`, `scaler.pkl`, `confusion_matrix.png`, `feature_importance.png`

## 🧪 Chạy Mininet
```bash
sudo mn --topo tree,depth=2 --controller=remote --mac
```

## 🧠 Chạy Ryu controller
```bash
ryu-manager ryu_ddos_controller.py
```

> Controller sẽ log cảnh báo 🔥 khi phát hiện tấn công

## 📊 Feature được trích xuất
Bao gồm 23 đặc trưng như: `pktcount`, `bytecount`, `pktperflow`, `pktrate`, `Protocol`, `tx_kbps`, `tot_dur`, v.v...

## ✅ Đầu ra mô hình
- Phát hiện chính xác (Accuracy > 99%)
- In cảnh báo ra log controller
- Dễ mở rộng để chặn (block) lưu lượng độc hại

## 📌 Gợi ý mở rộng
- Gửi log về hệ thống giám sát (Grafana/InfluxDB)
- Tự động chặn các flow độc hại
- Kết hợp với Prometheus Exporter

## 👤 Tác giả

- Ngô Anh Quang
- Nguyễn Duy Nhật Thành
- Đề tài: *Áp dụng kỹ thuật học máy để xây dựng hệ thống phát hiện và ngăn chặn xâm nhập trong mạng điều khiển bằng phần mềm*