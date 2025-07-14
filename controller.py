from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, ether_types
import pickle
import numpy as np
import time
from ryu.lib import hub
from operator import attrgetter
import pandas as pd

IDLE_TIMEOUT_FOR_STATS = 2 
DEFAULT_FLOW_PRIORITY = 1
ATTACK_BLOCK_PRIORITY = 10
MODEL_PATH = r'D:\môn học\DACN\beta\xgb_sdn_model_clean.pkl'

MONITORING_INTERVAL = 30.0 
MAX_SWITCHES = 10  
MAX_PORTS_PER_SWITCH = 5 

# --- Phát hiện tấn công ---
DETECTION_MIN_PACKETS = 10  # Số gói tin tối thiểu
DETECTION_MIN_DURATION = 1.0  # Thời gian tối thiểu
DETECTION_INTERVAL = 5.0  # Khoảng thời gian giữa các lần

class SDN_IDPS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDN_IDPS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flows = {} # Key:(src_ip, dst_ip, protocol).
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.active_flows_per_switch = {}  # {datapath_id: count}
        self.last_analysis_time = {}  # {flow_key: timestamp} để tránh phân tích quá thường xuyên
        self.early_detection_stats = {'analyzed': 0, 'detected': 0, 'blocked': 0}  # Thống kê phát hiện sớm

        self.model = None
        self.scaler = None
        self.feature_columns = None
        self.model_metrics = None
        self.label_encoders = None
        try:
            with open(MODEL_PATH, 'rb') as f:
                model_package = pickle.load(f)
            self.model = model_package['model']
            self.scaler = model_package['scaler']
            self.feature_columns = model_package['feature_columns']
            self.model_metrics = model_package['metrics']
            self.label_encoders = model_package.get('label_encoders', {})            
            self.logger.info("✅ Load mô hình XGBoost thành công!")
        except Exception:
            self.logger.error(f"❌ Không thể load mô hình!")

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            
            # Phân tích real-time các flow đang hoạt động để phát hiện tấn công sớm
            self._analyze_active_flows()
            
            hub.sleep(7)

    def _request_stats(self, datapath):
        # Gửi yêu cầu thống kê chung.
        self.logger.debug('Gửi yêu cầu thống kê đến switch: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req_flow = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req_flow)
        req_port = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req_port)

    def _analyze_active_flows(self):
        """
        Phân tích real-time các flow đang hoạt động để phát hiện tấn công sớm
        """
        if not self.model or not self.scaler:
            return

        current_time = time.time()
        flows_to_analyze = []

        # Tìm các flow có đủ điều kiện để phân tích sớm
        for flow_key, flow_data in self.flows.items():
            # Kiểm tra điều kiện phân tích sớm
            if self._should_analyze_flow_early(flow_key, flow_data, current_time):
                flows_to_analyze.append((flow_key, flow_data))

        # Phân tích các flow được chọn
        for flow_key, flow_data in flows_to_analyze:
            self._analyze_single_flow_early(flow_key, flow_data, current_time)

    def _should_analyze_flow_early(self, flow_key, flow_data, current_time):
        """
        Kiểm tra xem flow có nên được phân tích sớm hay không
        """
        # Kiểm tra số gói tin tối thiểu
        if flow_data['packet_count'] < DETECTION_MIN_PACKETS:
            return False

        # Kiểm tra thời gian tối thiểu
        duration = current_time - flow_data['start_time']
        if duration < DETECTION_MIN_DURATION:
            return False

        # Kiểm tra khoảng thời gian giữa các lần phân tích
        last_analysis = self.last_analysis_time.get(flow_key, 0)
        if current_time - last_analysis < DETECTION_INTERVAL:
            return False

        # Kiểm tra flow chưa bị chặn
        if flow_data.get('is_blocked', False):
            return False

        return True

    def _analyze_single_flow_early(self, flow_key, flow_data, current_time):
        """
        Phân tích một flow cụ thể để phát hiện tấn công sớm
        """
        try:
            # Cập nhật thời gian phân tích cuối
            self.last_analysis_time[flow_key] = current_time

            # Tính số flow hiện tại trên switch (ước tính)
            flows_count = len(self.flows)

            # Trích xuất features
            features_df = self.extract_features(flow_data, flows_count=flows_count)
            
            # Phân loại
            features_scaled = self.scaler.transform(features_df)
            prediction_probabilities = self.model.predict_proba(features_scaled)[0]
            predicted_class = self.model.predict(features_scaled)[0]
            malicious_probability = prediction_probabilities[1] if len(prediction_probabilities) > 1 else prediction_probabilities[0]
            confidence_score = malicious_probability * 100

            predicted_class_name = 'MALICIOUS' if predicted_class == 1 else 'BENIGN'

            # Cập nhật thống kê
            self.early_detection_stats['analyzed'] += 1
            
            # Hiển thị flow_key với protocol là tên giao thức
            src_ip, dst_ip, protocol = flow_key
            protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, f'PROTO_{protocol}')
            flow_key_str = (src_ip, dst_ip, protocol_name)

            # Log kết quả phân tích sớm
            self.logger.info(f"🔍 Flow {flow_key_str} - Class: {predicted_class_name}, Confidence: {confidence_score:.2f}%")

            # Nếu phát hiện tấn công với độ tin cậy cao
            if predicted_class == 1 and confidence_score > 70:  # Ngưỡng tin cậy 70%
                self.early_detection_stats['detected'] += 1
                self.logger.warning(f"🚨 DETECTION: Phát hiện tấn công sớm trong flow {flow_key_str}! Confidence: {confidence_score:.2f}%")
                
                # Đánh dấu flow đã bị chặn
                flow_data['is_blocked'] = True
                
                # Tìm datapath để cài rule chặn
                if self._block_flow_early(flow_key, flow_data):
                    self.early_detection_stats['blocked'] += 1

        except Exception as e:
            self.logger.error(f"❌ Lỗi khi phân tích flow {flow_key}: {str(e)}")

    def _block_flow_early(self, flow_key, flow_data):
        """
        Chặn flow sớm khi phát hiện tấn công
        """
        try:
            src_ip, dst_ip, protocol = flow_key
            protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, f'PROTO_{protocol}')
            flow_key_str = (src_ip, dst_ip, protocol_name)
            
            # Tìm datapath phù hợp dựa trên in_port của flow
            target_datapath = None
            in_port = flow_data.get('in_port')
            
            if in_port and self.datapaths:
                for datapath in self.datapaths.values():
                    target_datapath = datapath
                    break
            if not target_datapath and self.datapaths:
                target_datapath = list(self.datapaths.values())[0]
            
            if target_datapath:
                parser = target_datapath.ofproto_parser
                match_fields = {
                    'eth_type': ether_types.ETH_TYPE_IP,
                    'ipv4_src': src_ip,
                }
                block_match = parser.OFPMatch(**match_fields)
                self.add_flow(target_datapath, ATTACK_BLOCK_PRIORITY, block_match, [], hard_timeout=3600)
                self.logger.info(f"🚫 Đã cài rule chặn cho flow {flow_key_str} trên datapath {target_datapath.id}")
                return True
            else:
                self.logger.warning(f"⚠️ Không tìm thấy datapath để chặn flow {flow_key_str}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Lỗi khi chặn flow {flow_key}: {str(e)}")
            return False

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Đăng ký switch: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Hủy đăng ký switch: %016x', datapath.id)
                if datapath.id in self.datapaths:
                    del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        # Gom nhóm flow theo src_ip, dst_ip, protocol
        flow_groups = {}
        
        for stat in [flow for flow in body if flow.priority == 1]:
            # Lấy thông tin IP từ match fields
            src_ip = stat.match.get('ipv4_src')
            dst_ip = stat.match.get('ipv4_dst')
            protocol = stat.match.get('ip_proto')
            
            # Chỉ xử lý flow có thông tin IP
            if src_ip and dst_ip and protocol is not None:
                # Tạo key nhóm
                group_key = (src_ip, dst_ip, protocol)
                
                if group_key not in flow_groups:
                    flow_groups[group_key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': protocol,
                        'total_packets': 0,
                        'total_bytes': 0,
                        'flow_count': 0,
                        'ports': set()  # Tập hợp các port được sử dụng
                    }
                
                # Cộng dồn thống kê
                flow_groups[group_key]['total_packets'] += stat.packet_count
                flow_groups[group_key]['total_bytes'] += stat.byte_count
                flow_groups[group_key]['flow_count'] += 1
                
                # Thêm port vào tập hợp
                in_port = stat.match.get('in_port')
                if in_port is not None:
                    flow_groups[group_key]['ports'].add(in_port)
        
        # Hiển thị thống kê gom nhóm
        if flow_groups:
            self.logger.info('=== FLOW STATISTICS (GROUPED BY SRC/DST IP) ===')
            self.logger.info('datapath         src_ip          dst_ip          protocol  flows  packets    bytes    ports')
            self.logger.info('---------------- --------------- --------------- --------  -----  --------  --------  -----')
            
            # Sắp xếp theo tổng số packets (giảm dần)
            sorted_groups = sorted(flow_groups.items(), 
                                 key=lambda x: x[1]['total_packets'], reverse=True)
            
            for group_key, group_data in sorted_groups:
                src_ip, dst_ip, protocol = group_key
                protocol_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, f'PROTO{protocol}')
                ports_str = ','.join(map(str, sorted(group_data['ports']))) if group_data['ports'] else 'N/A'
                
                self.logger.info('%016x %15s %15s %8s %6d %8d %8d  %s',
                                ev.msg.datapath.id,
                                src_ip, dst_ip, protocol_name,
                                group_data['flow_count'],
                                group_data['total_packets'],
                                group_data['total_bytes'],
                                ports_str)
            
            # Thống kê tổng quan
            total_groups = len(flow_groups)
            total_flows = sum(g['flow_count'] for g in flow_groups.values())
            total_packets = sum(g['total_packets'] for g in flow_groups.values())
            total_bytes = sum(g['total_bytes'] for g in flow_groups.values())
            
            self.logger.info('=== SUMMARY ===')
            self.logger.info('Total IP groups: %d, Total flows: %d, Total packets: %d, Total bytes: %d',
                            total_groups, total_flows, total_packets, total_bytes)
        else:
            self.logger.info('No IP flows found in flow statistics')

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         port     '
                        'rx-pkts    rx-bytes   '
                        'tx-pkts    tx-bytes   ')
        self.logger.info('---------------- -------- '
                        '---------- ---------- '
                        '---------- ---------- ')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %10d %10d %10d %10d',
                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_packets, stat.rx_bytes,
                            stat.tx_packets, stat.tx_bytes)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0, flags=0):
        # Hàm tiện ích thêm flow rule. Các tham số idle_timeout và flags rất quan trọng cho IDPS.
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod_args = {
            'datapath': datapath, 'priority': priority, 'match': match,
            'instructions': inst, 'idle_timeout': idle_timeout, # Timeout để kích hoạt FlowRemoved.
            'hard_timeout': hard_timeout, 'flags': flags # Cờ OFPFF_SEND_FLOW_REM để nhận sự kiện.
        }
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
             mod_args['buffer_id'] = buffer_id
        mod = parser.OFPFlowMod(**mod_args)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Kiểm tra model và scaler trước khi xử lý cho IDPS.
        if not self.model or not self.scaler:
            self.logger.warning("IDPS: Model/Scaler chưa tải, bỏ qua xử lý PacketIn cho IDPS.")
            return

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions_packet_out = [parser.OFPActionOutput(out_port)]

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt: 
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            protocol = ipv4_pkt.proto
            packet_length = msg.total_len

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            src_port = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else 0)
            dst_port = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else 0)

            if protocol in [6, 17, 1]:  # TCP, UDP, ICMP
                flow_key = self.get_flow_key(src_ip, dst_ip, protocol)
                now = time.time()
                self.update_flow(flow_key, now, packet_length, tcp_pkt, ipv4_pkt, in_port)

                # Cập nhật số lượng flow đang hoạt động trên switch
                dpid_num = datapath.id
                self.active_flows_per_switch.setdefault(dpid_num, 0)
                self.active_flows_per_switch[dpid_num] += 1

                # Cài đặt flow rule tạm thời để thu thập thống kê và kích hoạt FlowRemoved.
                match_fields_dict = {'eth_type': ether_types.ETH_TYPE_IP, 'ipv4_src': src_ip, 'ipv4_dst': dst_ip, 'ip_proto': protocol}
                if tcp_pkt: match_fields_dict.update({'tcp_src': src_port, 'tcp_dst': dst_port})
                elif udp_pkt: match_fields_dict.update({'udp_src': src_port, 'udp_dst': dst_port})
                match_for_flow_rule = parser.OFPMatch(**match_fields_dict)

                # Thêm flow rule với idle_timeout và cờ OFPFF_SEND_FLOW_REM.
                self.add_flow(datapath, DEFAULT_FLOW_PRIORITY, match_for_flow_rule, actions_packet_out,
                                msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else None,
                                idle_timeout=IDLE_TIMEOUT_FOR_STATS, # Quan trọng cho việc kích hoạt FlowRemoved.
                                flags=ofproto.OFPFF_SEND_FLOW_REM)   # Quan trọng để nhận sự kiện.
        
        # Gửi gói tin PacketIn hiện tại ra ngoài.
        data_to_send = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out_message = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions_packet_out, data=data_to_send)
        datapath.send_msg(out_message)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        """
        Khi xóa flow, ghi log thông tin flow bị xóa.
        """
        msg = ev.msg
        datapath = msg.datapath
        match_fields = msg.match
        src_ip = match_fields.get('ipv4_src')
        dst_ip = match_fields.get('ipv4_dst')
        protocol = match_fields.get('ip_proto')
        if not (src_ip and dst_ip and protocol is not None):
            return

        flow_key_reconstructed = self.get_flow_key(src_ip, dst_ip, protocol)
        if flow_key_reconstructed in self.flows:
            del self.flows[flow_key_reconstructed]
        dpid_num = datapath.id
        if dpid_num in self.active_flows_per_switch and self.active_flows_per_switch[dpid_num] > 0:
            self.active_flows_per_switch[dpid_num] -= 1

    def get_flow_key(self, src_ip, dst_ip, protocol):
        # Tạo key chỉ dựa trên src_ip, dst_ip, protocol để gom các flow theo đúng dataset
        return (src_ip, dst_ip, protocol)

    def get_reverse_flow_key(self, src_ip, dst_ip, protocol):
        # Tạo key cho flow ngược lại
        return (dst_ip, src_ip, protocol)

    def check_pairflow(self, flow_key):
        """
        Kiểm tra xem có paired flow (bidirectional) hay không
        Returns: 1 nếu có paired flow, 0 nếu không
        """
        src_ip, dst_ip, protocol = flow_key
        reverse_key = self.get_reverse_flow_key(src_ip, dst_ip, protocol)
        return 1 if reverse_key in self.flows else 0

    def update_flow(self, flow_key, now, packet_length, tcp_pkt, ipv4_pkt, in_port=None):
        """
        Cập nhật thông tin thống kê cho flow theo chuẩn dataset SDN.
        Lưu trữ đầy đủ thông tin để tính toán 23 features.
        """
        # Lấy thông tin port từ flow_key để lưu vào flow_stats
        src_ip, dst_ip, protocol_info = flow_key
        
        flow_stats = self.flows.setdefault(flow_key, {
            'start_time': now, 'last_time': now,
            'packet_times': [],
            'packet_lengths': [],
            'packet_count': 0,
            'total_bytes': 0,
            # Thông tin cơ bản cho features
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol_info,
            'in_port': in_port,
            'is_blocked': False,
            # Thông tin bổ sung cho tính toán chính xác
            'first_packet_time': now,
            'last_packet_time': now,
            'tx_bytes': 0,  # Bytes truyền
            'rx_bytes': 0,  # Bytes nhận
            'packet_ins_count': 0,  # Số lượng Packet_in messages
        })

        flow_stats['last_time'] = now
        flow_stats['last_packet_time'] = now
        flow_stats['packet_times'].append(now)
        flow_stats['packet_lengths'].append(packet_length)
        flow_stats['packet_count'] += 1
        flow_stats['total_bytes'] += packet_length
        flow_stats['packet_ins_count'] += 1  # Mỗi packet tạo ra một Packet_in

        # Tính toán tx_bytes và rx_bytes (đơn giản: chia đôi)
        flow_stats['tx_bytes'] = flow_stats['total_bytes'] // 2
        flow_stats['rx_bytes'] = flow_stats['total_bytes'] - flow_stats['tx_bytes'] 

    def extract_features(self, flow_data_dict, flows_count=1, datapath_id=None):
        """
        Trích xuất features từ flow data theo đúng format của dataset SDN
        Dựa trên mô tả: 23 features được trích xuất từ switches và tính toán
        
        EXTRACTED FEATURES (từ switches):
        - Switch-id, Packet_count, byte_count, duration_sec, duration_nsec
        - Source IP, Destination IP, Port number, tx_bytes, rx_bytes, dt
        
        CALCULATED FEATURES (tính toán):
        - Packet per flow, Byte per flow, Packet Rate, Packet_ins
        - Total flow entries, tx_kbps, rx_kbps, Port Bandwidth
        - Pairflow, Protocol, Total kbps
        """
        # --- Tính toán các giá trị cơ bản ---
        duration = flow_data_dict['last_time'] - flow_data_dict['start_time']
        if duration <= 0: duration = 1e-6 # Tránh chia cho 0.

        # Lấy dữ liệu từ flow_data_dict
        packet_lengths_array = np.array(flow_data_dict['packet_lengths']) if flow_data_dict['packet_lengths'] else np.array([0.0])

        # --- EXTRACTED FEATURES (từ switches) ---
        
        # 1. Switch-id: ID của switch
        if datapath_id is not None:
            switch_id = datapath_id % MAX_SWITCHES  # Đảm bảo trong phạm vi 0-9
        else:
            switch_id = 0  # Default switch ID
        
        # 2. Packet_count: Số lượng gói tin trong flow
        pktcount = flow_data_dict['packet_count']
        
        # 3. Byte_count: Tổng số bytes trong flow
        bytecount = flow_data_dict['total_bytes']
        
        # 4. Duration_sec: Thời gian flow (giây)
        dur_sec = int(duration)
        
        # 5. Duration_nsec: Thời gian flow (nano giây)
        dur_nsec = int(duration * 1_000_000_000)
        
        # 6. Total_duration: Tổng thời gian (nano giây)
        tot_dur = dur_nsec
        
        # 7. Source IP: IP nguồn (encoded)
        src_ip = flow_data_dict.get('src_ip', '10.0.0.1')
        if self.label_encoders and 'src' in self.label_encoders:
            try:
                src = self.label_encoders['src'].transform([src_ip])[0]
            except ValueError:
                src = 0
        else:
            try:
                src_last_octet = int(src_ip.split('.')[-1]) if src_ip else 1
                src = max(0, min(18, src_last_octet - 1))
            except:
                src = 0
        
        # 8. Destination IP: IP đích (encoded)
        dst_ip = flow_data_dict.get('dst_ip', '10.0.0.8')
        if self.label_encoders and 'dst' in self.label_encoders:
            try:
                dst = self.label_encoders['dst'].transform([dst_ip])[0]
            except ValueError:
                dst = 16
        else:
            try:
                dst_last_octet = int(dst_ip.split('.')[-1]) if dst_ip else 8
                dst = max(0, min(17, dst_last_octet - 1))
            except:
                dst = 16
        
        # 9. Port number: Số hiệu cổng switch
        port_no_raw = flow_data_dict.get('in_port', 1)
        if self.label_encoders and 'port_no' in self.label_encoders:
            try:
                port_no = self.label_encoders['port_no'].transform([port_no_raw])[0]
            except ValueError:
                port_no = 0
        else:
            port_no = (port_no_raw - 1) % 5
        
        # 10. tx_bytes: Bytes truyền từ switch port
        tx_bytes = flow_data_dict.get('tx_bytes', bytecount // 2)
        
        # 11. rx_bytes: Bytes nhận trên switch port
        rx_bytes = flow_data_dict.get('rx_bytes', bytecount - tx_bytes)
        
        # 12. dt: Date and time (converted to number) - sử dụng timestamp
        dt = int(flow_data_dict['start_time'])
        
        # --- CALCULATED FEATURES (tính toán) ---
        
        # 13. Packet per flow: Số gói tin trong một flow
        packetperflow = pktcount
        
        # 14. Byte per flow: Số bytes trong một flow
        byteperflow = bytecount
        
        # 15. Packet Rate: Số gói tin/giây (monitoring interval = 30s)
        # Theo mô tả: "Packet Rate is number of packets send per second and calculated by dividing the packet per flow by monitoring interval"
        packet_rate = pktcount / MONITORING_INTERVAL if MONITORING_INTERVAL > 0 else 0
        
        # 16. Packet_ins: Số lượng Packet_in messages
        packetins = flow_data_dict.get('packet_ins_count', pktcount)  # Sử dụng giá trị đã lưu trữ
        
        # 17. Total flow entries: Tổng số flow entries trong switch
        flows = flows_count
        
        # 18. tx_kbps: Tốc độ truyền dữ liệu (Kbps)
        tx_kbps = (tx_bytes * 8 / 1000) / duration if duration > 0 else 0
        
        # 19. rx_kbps: Tốc độ nhận dữ liệu (Kbps)
        rx_kbps = (rx_bytes * 8 / 1000) / duration if duration > 0 else 0
        
        # 20. Port Bandwidth: Tổng băng thông cổng (tx_kbps + rx_kbps)
        port_bandwidth = tx_kbps + rx_kbps
        
        # 21. Pairflow: Kiểm tra có flow ngược lại không
        flow_key = (flow_data_dict.get('src_ip', ''), flow_data_dict.get('dst_ip', ''), flow_data_dict.get('protocol', 0))
        Pairflow = self.check_pairflow(flow_key)
        
        # 22. Protocol: Loại giao thức (encoded)
        protocol_raw = flow_data_dict.get('protocol', 17)
        if protocol_raw == 6:      # TCP
            protocol_name = 'TCP'
        elif protocol_raw == 17:   # UDP  
            protocol_name = 'UDP'
        elif protocol_raw == 1:    # ICMP
            protocol_name = 'ICMP'
        else:
            protocol_name = 'UDP'
        
        if self.label_encoders and 'Protocol' in self.label_encoders:
            try:
                Protocol = self.label_encoders['Protocol'].transform([protocol_name])[0]
            except ValueError:
                Protocol = 0
        else:
            if protocol_name == 'TCP':
                Protocol = 1
            elif protocol_name == 'UDP':
                Protocol = 2
            elif protocol_name == 'ICMP':
                Protocol = 0
            else:
                Protocol = 2
        
        # 23. Total kbps: Tổng tốc độ truyền nhận
        tot_kbps = (bytecount * 8 / 1000) / duration if duration > 0 else 0

        # --- Tạo DataFrame với đúng thứ tự features từ model ---
        if self.feature_columns:
            # Sử dụng thứ tự features từ model đã train
            feature_values = []
            for feature in self.feature_columns:
                if feature == 'switch':
                    feature_values.append(switch_id)
                elif feature == 'src':
                    feature_values.append(src)
                elif feature == 'dst':
                    feature_values.append(dst)
                elif feature == 'pktcount':
                    feature_values.append(pktcount)
                elif feature == 'bytecount':
                    feature_values.append(bytecount)
                elif feature == 'dur':
                    feature_values.append(dur_sec)
                elif feature == 'dur_nsec':
                    feature_values.append(dur_nsec)
                elif feature == 'tot_dur':
                    feature_values.append(tot_dur)
                elif feature == 'flows':
                    feature_values.append(flows)
                elif feature == 'packetins':
                    feature_values.append(packetins)
                elif feature == 'byteperflow':
                    feature_values.append(byteperflow)
                elif feature == 'Pairflow':
                    feature_values.append(Pairflow)
                elif feature == 'Protocol':
                    feature_values.append(Protocol)
                elif feature == 'port_no':
                    feature_values.append(port_no)
                elif feature == 'tx_bytes':
                    feature_values.append(tx_bytes)
                elif feature == 'rx_bytes':
                    feature_values.append(rx_bytes)
                elif feature == 'rx_kbps':
                    feature_values.append(rx_kbps)
                elif feature == 'tot_kbps':
                    feature_values.append(tot_kbps)
                elif feature == 'dt':
                    feature_values.append(dt)
                elif feature == 'packetperflow':
                    feature_values.append(packetperflow)
                elif feature == 'packet_rate':
                    feature_values.append(packet_rate)
                elif feature == 'tx_kbps':
                    feature_values.append(tx_kbps)
                elif feature == 'port_bandwidth':
                    feature_values.append(port_bandwidth)
                else:
                    feature_values.append(0)  # Default value for unknown features
            
            features_df = pd.DataFrame([feature_values], columns=self.feature_columns)
        else:
            # Fallback nếu không có feature_columns - sử dụng thứ tự theo mô tả dataset
            self.logger.warning("IDPS: Không có feature_columns từ model, sử dụng thứ tự theo mô tả dataset")
            feature_names = [
                'switch', 'src', 'dst', 'pktcount', 'bytecount', 'dur', 'dur_nsec', 'tot_dur',
                'packetperflow', 'byteperflow', 'packet_rate', 'packetins', 'flows', 'tx_kbps', 
                'rx_kbps', 'port_bandwidth', 'Pairflow', 'Protocol', 'port_no', 'tx_bytes', 
                'rx_bytes', 'dt', 'tot_kbps'
            ]
            features_list = [
                switch_id, src, dst, pktcount, bytecount, dur_sec, dur_nsec, tot_dur,
                packetperflow, byteperflow, packet_rate, packetins, flows, tx_kbps,
                rx_kbps, port_bandwidth, Pairflow, Protocol, port_no, tx_bytes,
                rx_bytes, dt, tot_kbps
            ]
            features_df = pd.DataFrame([features_list], columns=feature_names)
        
        return features_df   