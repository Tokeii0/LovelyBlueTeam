package main

const (
	version        = "1.0.0-demo"
	appName        = "Lovely.UDS.Demo"
	appTitle       = "Lovely UDS · 离线合成数据演示"
	centerEndpoint = "http://192.0.2.14:8220"
)

type udsChannel struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Agent    string `json:"agent"`
	Peer     string `json:"peer"`
	Dir      string `json:"dir"`      // 上行 / 下行 / 双向
	Interval int    `json:"interval"` // 秒
	Status   string `json:"status"`   // 正常 / 停用 / 告警
	Pending  int    `json:"pending"`  // 待传条数
}

var udsChannels = []udsChannel{
	{ID: "CH-HIS-ADT-01", Name: "HIS 患者主索引(ADT)同步", Agent: "Oracle", Peer: "192.0.2.104:1521/HISDB", Dir: "上行", Interval: 30, Status: "正常", Pending: 412},
	{ID: "CH-HIS-ORD-02", Name: "HIS 医嘱状态回写", Agent: "Oracle", Peer: "192.0.2.104:1521/HISDB", Dir: "下行", Interval: 15, Status: "正常", Pending: 38},
	{ID: "CH-EMR-DOC-03", Name: "EMR 病历文书推送", Agent: "WebApi", Peer: "192.0.2.105:8083/emr/api", Dir: "上行", Interval: 60, Status: "正常", Pending: 96},
	{ID: "CH-LIS-RPT-04", Name: "LIS 检验报告回传", Agent: "MySQL", Peer: "192.0.2.61:3306/lisdb", Dir: "上行", Interval: 20, Status: "正常", Pending: 520},
	{ID: "CH-PACS-IDX-05", Name: "PACS 影像索引回传", Agent: "FTP", Peer: "192.0.2.60:21/pacs/idx", Dir: "上行", Interval: 120, Status: "正常", Pending: 12},
	{ID: "CH-DRG-HERB-06", Name: "中草药房库存同步(达梦)", Agent: "Dameng", Peer: "192.0.2.26:5236/HISDB", Dir: "双向", Interval: 300, Status: "告警", Pending: 126},
	{ID: "CH-OA-MSG-07", Name: "OA 通知下发", Agent: "WebApi", Peer: "192.0.2.16:8090/oa/api", Dir: "下行", Interval: 60, Status: "停用", Pending: 0},
}

// ===================== 仿真接口调用 =====================
// invoke 命令与各命令的阶段输出按标准接口调用形态组织：
// 会话认证（JWT）→ 标准接口方法试调 → 心跳保活。以下为伪装的接口
// 注册表与应答生成所用的演示数据，均为虚构内容。

// udsInterface 是仿真接口注册表条目：方法名按真实 UDS AgentInterface 习惯命名。
type udsInterface struct {
	Method string `json:"method"`
	Desc   string `json:"desc"`
}

var udsInterfaces = []udsInterface{
	{"PatientService.GetPatientInfo", "病人信息查询"},
	{"PatientService.GetVisitList", "就诊记录列表"},
	{"HisService.GetOrderList", "医嘱列表"},
	{"LisService.GetReportList", "检验报告列表"},
	{"LisService.GetResultDetail", "检验结果明细"},
	{"PacsService.GetImageIndex", "影像索引查询"},
	{"EmrService.GetDocList", "病历文书列表"},
	{"ChannelService.ListAll", "通道清单"},
	{"QueueService.PendingStat", "待传队列统计"},
	{"SystemService.GetServerTime", "中心端时间"},
}

// 仿真病人信息：就诊号经 FNV-1a 确定性映射，同一输入永远返回同一份记录。
var patientNames = []string{"测试患者甲", "测试患者乙", "测试患者丙", "测试患者丁"}

var patientDepts = []string{
	"心血管内科", "呼吸内科", "消化内科", "神经内科",
	"普外科", "骨科", "妇产科", "儿科",
}

var patientDiags = []string{
	"冠心病", "高血压3级", "2型糖尿病", "慢性阻塞性肺疾病",
	"急性上呼吸道感染", "腰椎间盘突出", "胆囊结石", "社区获得性肺炎",
}

// 仿真检验报告目录：院内 LIS 不止血常规——一条码可对应多种检验 panel。
// Row 带 Pool 的为定性项目（- / + / ++），否则按 Base±Jitter 生成数值并标 ↑/↓。
type lisAnalyte struct {
	Code, Name, Unit, Ref string
	Base, Jitter          float64
	Pool                  []string
}

type lisPanel struct {
	Item       string
	SampleType string
	Aliases    []string
	Rows       []lisAnalyte
}

var lisCatalog = []lisPanel{
	{"血常规（五分类）", "全血", []string{"cbc", "blood", "血常规", "血球"}, []lisAnalyte{
		{Code: "WBC", Name: "白细胞计数", Unit: "10^9/L", Ref: "3.5-9.5", Base: 6.4, Jitter: 4.5},
		{Code: "NEUT%", Name: "中性粒细胞比率", Unit: "%", Ref: "40-75", Base: 62, Jitter: 18},
		{Code: "LYMPH%", Name: "淋巴细胞比率", Unit: "%", Ref: "20-50", Base: 30, Jitter: 12},
		{Code: "MONO%", Name: "单核细胞比率", Unit: "%", Ref: "3-10", Base: 6.5, Jitter: 3},
		{Code: "EO%", Name: "嗜酸性粒细胞比率", Unit: "%", Ref: "0.4-8", Base: 2.5, Jitter: 3},
		{Code: "BASO%", Name: "嗜碱性粒细胞比率", Unit: "%", Ref: "0-1", Base: 0.5, Jitter: 0.6},
		{Code: "RBC", Name: "红细胞计数", Unit: "10^12/L", Ref: "3.8-5.8", Base: 4.6, Jitter: 1.2},
		{Code: "HGB", Name: "血红蛋白", Unit: "g/L", Ref: "115-150", Base: 132, Jitter: 25},
		{Code: "HCT", Name: "红细胞压积", Unit: "%", Ref: "35-45", Base: 40, Jitter: 5},
		{Code: "MCV", Name: "平均红细胞体积", Unit: "fL", Ref: "82-100", Base: 90, Jitter: 8},
		{Code: "MCH", Name: "平均血红蛋白量", Unit: "pg", Ref: "27-34", Base: 30, Jitter: 3},
		{Code: "MCHC", Name: "平均血红蛋白浓度", Unit: "g/L", Ref: "316-354", Base: 335, Jitter: 12},
		{Code: "PLT", Name: "血小板计数", Unit: "10^9/L", Ref: "125-350", Base: 210, Jitter: 90},
	}},
	{"尿常规", "尿液", []string{"urine", "ua", "尿常规", "尿检"}, []lisAnalyte{
		{Code: "PH", Name: "酸碱度", Unit: "", Ref: "4.5-8.0", Base: 6.0, Jitter: 1.2},
		{Code: "SG", Name: "比重", Unit: "", Ref: "1.003-1.030", Base: 1.015, Jitter: 0.01},
		{Code: "LEU", Name: "白细胞", Unit: "", Ref: "-", Pool: []string{"-", "-", "-", "+"}},
		{Code: "NIT", Name: "亚硝酸盐", Unit: "", Ref: "-", Pool: []string{"-", "-", "-", "-", "+"}},
		{Code: "GLU", Name: "葡萄糖", Unit: "", Ref: "-", Pool: []string{"-", "-", "-", "+"}},
		{Code: "PRO", Name: "蛋白质", Unit: "", Ref: "-", Pool: []string{"-", "-", "-", "+", "++"}},
		{Code: "BLD", Name: "隐血", Unit: "", Ref: "-", Pool: []string{"-", "-", "-", "+"}},
		{Code: "KET", Name: "酮体", Unit: "", Ref: "-", Pool: []string{"-", "-", "-", "-", "+"}},
		{Code: "URO", Name: "尿胆原", Unit: "", Ref: "-", Pool: []string{"-", "-", "-", "+"}},
		{Code: "BIL", Name: "胆红素", Unit: "", Ref: "-", Pool: []string{"-", "-", "-", "-", "+"}},
		{Code: "WBC.HP", Name: "白细胞（镜检）", Unit: "/HP", Ref: "0-5", Base: 2, Jitter: 4},
		{Code: "RBC.HP", Name: "红细胞（镜检）", Unit: "/HP", Ref: "0-3", Base: 1, Jitter: 3},
	}},
	{"生化全套", "血清", []string{"biochem", "chem", "生化", "肝肾功"}, []lisAnalyte{
		{Code: "ALT", Name: "丙氨酸氨基转移酶", Unit: "U/L", Ref: "9-50", Base: 22, Jitter: 18},
		{Code: "AST", Name: "天冬氨酸氨基转移酶", Unit: "U/L", Ref: "15-40", Base: 24, Jitter: 14},
		{Code: "TBIL", Name: "总胆红素", Unit: "μmol/L", Ref: "5-21", Base: 11, Jitter: 8},
		{Code: "DBIL", Name: "直接胆红素", Unit: "μmol/L", Ref: "0-6.8", Base: 3.5, Jitter: 3},
		{Code: "ALB", Name: "白蛋白", Unit: "g/L", Ref: "40-55", Base: 45, Jitter: 6},
		{Code: "BUN", Name: "尿素氮", Unit: "mmol/L", Ref: "2.9-8.2", Base: 5.2, Jitter: 2.5},
		{Code: "CREA", Name: "肌酐", Unit: "μmol/L", Ref: "59-104", Base: 74, Jitter: 25},
		{Code: "UA", Name: "尿酸", Unit: "μmol/L", Ref: "208-428", Base: 330, Jitter: 90},
		{Code: "GLU", Name: "空腹血糖", Unit: "mmol/L", Ref: "3.9-6.1", Base: 5.1, Jitter: 2.2},
		{Code: "K", Name: "钾", Unit: "mmol/L", Ref: "3.5-5.3", Base: 4.2, Jitter: 0.9},
		{Code: "NA", Name: "钠", Unit: "mmol/L", Ref: "137-147", Base: 141, Jitter: 4},
		{Code: "CL", Name: "氯", Unit: "mmol/L", Ref: "99-110", Base: 103, Jitter: 5},
		{Code: "CA", Name: "钙", Unit: "mmol/L", Ref: "2.11-2.52", Base: 2.3, Jitter: 0.2},
		{Code: "TC", Name: "总胆固醇", Unit: "mmol/L", Ref: "2.8-5.2", Base: 4.3, Jitter: 1.4},
		{Code: "TG", Name: "甘油三酯", Unit: "mmol/L", Ref: "0.45-1.7", Base: 1.1, Jitter: 1.1},
		{Code: "HDL-C", Name: "高密度脂蛋白", Unit: "mmol/L", Ref: "1.03-1.89", Base: 1.4, Jitter: 0.5},
		{Code: "LDL-C", Name: "低密度脂蛋白", Unit: "mmol/L", Ref: "0-3.4", Base: 2.5, Jitter: 1.2},
	}},
	{"凝血四项", "血浆", []string{"coag", "凝血", "pt", "aptt"}, []lisAnalyte{
		{Code: "PT", Name: "凝血酶原时间", Unit: "s", Ref: "9-13.5", Base: 11.5, Jitter: 2.5},
		{Code: "INR", Name: "国际标准化比值", Unit: "", Ref: "0.8-1.2", Base: 1.0, Jitter: 0.25},
		{Code: "APTT", Name: "活化部分凝血活酶时间", Unit: "s", Ref: "25-35", Base: 30, Jitter: 5.5},
		{Code: "TT", Name: "凝血酶时间", Unit: "s", Ref: "14-21", Base: 17, Jitter: 3.5},
		{Code: "FIB", Name: "纤维蛋白原", Unit: "g/L", Ref: "2-4", Base: 2.9, Jitter: 1.1},
		{Code: "D-D", Name: "D-二聚体", Unit: "mg/L", Ref: "0-0.55", Base: 0.3, Jitter: 0.45},
	}},
	{"血气分析", "动脉血", []string{"gas", "bga", "血气"}, []lisAnalyte{
		{Code: "PH", Name: "酸碱度", Unit: "", Ref: "7.35-7.45", Base: 7.40, Jitter: 0.07},
		{Code: "PCO2", Name: "二氧化碳分压", Unit: "mmHg", Ref: "35-45", Base: 40, Jitter: 7},
		{Code: "PO2", Name: "氧分压", Unit: "mmHg", Ref: "83-108", Base: 95, Jitter: 15},
		{Code: "HCO3", Name: "碳酸氢根", Unit: "mmol/L", Ref: "21.4-27.3", Base: 24.5, Jitter: 3},
		{Code: "BE", Name: "碱剩余", Unit: "mmol/L", Ref: "-3-3", Base: 0, Jitter: 3.5},
		{Code: "SO2", Name: "氧饱和度", Unit: "%", Ref: "95-98", Base: 96.5, Jitter: 2.5},
		{Code: "LAC", Name: "乳酸", Unit: "mmol/L", Ref: "0.5-1.6", Base: 1.1, Jitter: 0.9},
	}},
	{"感染免疫", "血清", []string{"immuno", "crp", "pct", "免疫", "感染", "乙肝"}, []lisAnalyte{
		{Code: "CRP", Name: "C反应蛋白", Unit: "mg/L", Ref: "0-8", Base: 5, Jitter: 12},
		{Code: "PCT", Name: "降钙素原", Unit: "ng/mL", Ref: "0-0.5", Base: 0.12, Jitter: 0.5},
		{Code: "HBsAg", Name: "乙肝表面抗原", Unit: "IU/mL", Ref: "0-0.05", Base: 0.01, Jitter: 0.03},
		{Code: "HBsAb", Name: "乙肝表面抗体", Unit: "mIU/mL", Ref: "0-10", Base: 6, Jitter: 60},
		{Code: "HBeAg", Name: "乙肝e抗原", Unit: "S/CO", Ref: "0-1", Base: 0.2, Jitter: 0.4},
		{Code: "HBeAb", Name: "乙肝e抗体", Unit: "S/CO", Ref: ">1", Base: 2.5, Jitter: 1.5},
		{Code: "HBcAb", Name: "乙肝核心抗体", Unit: "S/CO", Ref: ">1", Base: 3.0, Jitter: 1.5},
	}},
	{"心肌标志物", "血清", []string{"cardiac", "心肌", "肌钙", "bnp"}, []lisAnalyte{
		{Code: "cTnI", Name: "肌钙蛋白I", Unit: "ng/mL", Ref: "0-0.04", Base: 0.01, Jitter: 0.03},
		{Code: "CK-MB", Name: "肌酸激酶同工酶", Unit: "U/L", Ref: "0-24", Base: 12, Jitter: 10},
		{Code: "MYO", Name: "肌红蛋白", Unit: "ng/mL", Ref: "0-70", Base: 35, Jitter: 40},
		{Code: "NT-proBNP", Name: "N末端脑钠肽前体", Unit: "pg/mL", Ref: "0-125", Base: 60, Jitter: 90},
	}},
}
