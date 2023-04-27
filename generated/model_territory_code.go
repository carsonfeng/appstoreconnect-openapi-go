/*
App Store Connect API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2.3
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"encoding/json"
	"fmt"
)

// TerritoryCode the model 'TerritoryCode'
type TerritoryCode string

// List of TerritoryCode
const (
	ABW TerritoryCode = "ABW"
	AFG TerritoryCode = "AFG"
	AGO TerritoryCode = "AGO"
	AIA TerritoryCode = "AIA"
	ALB TerritoryCode = "ALB"
	AND TerritoryCode = "AND"
	ANT TerritoryCode = "ANT"
	ARE TerritoryCode = "ARE"
	ARG TerritoryCode = "ARG"
	ARM TerritoryCode = "ARM"
	ASM TerritoryCode = "ASM"
	ATG TerritoryCode = "ATG"
	AUS TerritoryCode = "AUS"
	AUT TerritoryCode = "AUT"
	AZE TerritoryCode = "AZE"
	BDI TerritoryCode = "BDI"
	BEL TerritoryCode = "BEL"
	BEN TerritoryCode = "BEN"
	BES TerritoryCode = "BES"
	BFA TerritoryCode = "BFA"
	BGD TerritoryCode = "BGD"
	BGR TerritoryCode = "BGR"
	BHR TerritoryCode = "BHR"
	BHS TerritoryCode = "BHS"
	BIH TerritoryCode = "BIH"
	BLR TerritoryCode = "BLR"
	BLZ TerritoryCode = "BLZ"
	BMU TerritoryCode = "BMU"
	BOL TerritoryCode = "BOL"
	BRA TerritoryCode = "BRA"
	BRB TerritoryCode = "BRB"
	BRN TerritoryCode = "BRN"
	BTN TerritoryCode = "BTN"
	BWA TerritoryCode = "BWA"
	CAF TerritoryCode = "CAF"
	CAN TerritoryCode = "CAN"
	CHE TerritoryCode = "CHE"
	CHL TerritoryCode = "CHL"
	CHN TerritoryCode = "CHN"
	CIV TerritoryCode = "CIV"
	CMR TerritoryCode = "CMR"
	COD TerritoryCode = "COD"
	COG TerritoryCode = "COG"
	COK TerritoryCode = "COK"
	COL TerritoryCode = "COL"
	COM TerritoryCode = "COM"
	CPV TerritoryCode = "CPV"
	CRI TerritoryCode = "CRI"
	CUB TerritoryCode = "CUB"
	CUW TerritoryCode = "CUW"
	CXR TerritoryCode = "CXR"
	CYM TerritoryCode = "CYM"
	CYP TerritoryCode = "CYP"
	CZE TerritoryCode = "CZE"
	DEU TerritoryCode = "DEU"
	DJI TerritoryCode = "DJI"
	DMA TerritoryCode = "DMA"
	DNK TerritoryCode = "DNK"
	DOM TerritoryCode = "DOM"
	DZA TerritoryCode = "DZA"
	ECU TerritoryCode = "ECU"
	EGY TerritoryCode = "EGY"
	ERI TerritoryCode = "ERI"
	ESP TerritoryCode = "ESP"
	EST TerritoryCode = "EST"
	ETH TerritoryCode = "ETH"
	FIN TerritoryCode = "FIN"
	FJI TerritoryCode = "FJI"
	FLK TerritoryCode = "FLK"
	FRA TerritoryCode = "FRA"
	FRO TerritoryCode = "FRO"
	FSM TerritoryCode = "FSM"
	GAB TerritoryCode = "GAB"
	GBR TerritoryCode = "GBR"
	GEO TerritoryCode = "GEO"
	GGY TerritoryCode = "GGY"
	GHA TerritoryCode = "GHA"
	GIB TerritoryCode = "GIB"
	GIN TerritoryCode = "GIN"
	GLP TerritoryCode = "GLP"
	GMB TerritoryCode = "GMB"
	GNB TerritoryCode = "GNB"
	GNQ TerritoryCode = "GNQ"
	GRC TerritoryCode = "GRC"
	GRD TerritoryCode = "GRD"
	GRL TerritoryCode = "GRL"
	GTM TerritoryCode = "GTM"
	GUF TerritoryCode = "GUF"
	GUM TerritoryCode = "GUM"
	GUY TerritoryCode = "GUY"
	HKG TerritoryCode = "HKG"
	HND TerritoryCode = "HND"
	HRV TerritoryCode = "HRV"
	HTI TerritoryCode = "HTI"
	HUN TerritoryCode = "HUN"
	IDN TerritoryCode = "IDN"
	IMN TerritoryCode = "IMN"
	IND TerritoryCode = "IND"
	IRL TerritoryCode = "IRL"
	IRQ TerritoryCode = "IRQ"
	ISL TerritoryCode = "ISL"
	ISR TerritoryCode = "ISR"
	ITA TerritoryCode = "ITA"
	JAM TerritoryCode = "JAM"
	JEY TerritoryCode = "JEY"
	JOR TerritoryCode = "JOR"
	JPN TerritoryCode = "JPN"
	KAZ TerritoryCode = "KAZ"
	KEN TerritoryCode = "KEN"
	KGZ TerritoryCode = "KGZ"
	KHM TerritoryCode = "KHM"
	KIR TerritoryCode = "KIR"
	KNA TerritoryCode = "KNA"
	KOR TerritoryCode = "KOR"
	KWT TerritoryCode = "KWT"
	LAO TerritoryCode = "LAO"
	LBN TerritoryCode = "LBN"
	LBR TerritoryCode = "LBR"
	LBY TerritoryCode = "LBY"
	LCA TerritoryCode = "LCA"
	LIE TerritoryCode = "LIE"
	LKA TerritoryCode = "LKA"
	LSO TerritoryCode = "LSO"
	LTU TerritoryCode = "LTU"
	LUX TerritoryCode = "LUX"
	LVA TerritoryCode = "LVA"
	//MAC TerritoryCode = "MAC"
	MAR TerritoryCode = "MAR"
	MCO TerritoryCode = "MCO"
	MDA TerritoryCode = "MDA"
	MDG TerritoryCode = "MDG"
	MDV TerritoryCode = "MDV"
	MEX TerritoryCode = "MEX"
	MHL TerritoryCode = "MHL"
	MKD TerritoryCode = "MKD"
	MLI TerritoryCode = "MLI"
	MLT TerritoryCode = "MLT"
	MMR TerritoryCode = "MMR"
	MNE TerritoryCode = "MNE"
	MNG TerritoryCode = "MNG"
	MNP TerritoryCode = "MNP"
	MOZ TerritoryCode = "MOZ"
	MRT TerritoryCode = "MRT"
	MSR TerritoryCode = "MSR"
	MTQ TerritoryCode = "MTQ"
	MUS TerritoryCode = "MUS"
	MWI TerritoryCode = "MWI"
	MYS TerritoryCode = "MYS"
	MYT TerritoryCode = "MYT"
	NAM TerritoryCode = "NAM"
	NCL TerritoryCode = "NCL"
	NER TerritoryCode = "NER"
	NFK TerritoryCode = "NFK"
	NGA TerritoryCode = "NGA"
	NIC TerritoryCode = "NIC"
	NIU TerritoryCode = "NIU"
	NLD TerritoryCode = "NLD"
	NOR TerritoryCode = "NOR"
	NPL TerritoryCode = "NPL"
	NRU TerritoryCode = "NRU"
	NZL TerritoryCode = "NZL"
	OMN TerritoryCode = "OMN"
	PAK TerritoryCode = "PAK"
	PAN TerritoryCode = "PAN"
	PER TerritoryCode = "PER"
	PHL TerritoryCode = "PHL"
	PLW TerritoryCode = "PLW"
	PNG TerritoryCode = "PNG"
	POL TerritoryCode = "POL"
	PRI TerritoryCode = "PRI"
	PRT TerritoryCode = "PRT"
	PRY TerritoryCode = "PRY"
	PSE TerritoryCode = "PSE"
	PYF TerritoryCode = "PYF"
	QAT TerritoryCode = "QAT"
	REU TerritoryCode = "REU"
	ROU TerritoryCode = "ROU"
	RUS TerritoryCode = "RUS"
	RWA TerritoryCode = "RWA"
	SAU TerritoryCode = "SAU"
	SEN TerritoryCode = "SEN"
	SGP TerritoryCode = "SGP"
	SHN TerritoryCode = "SHN"
	SLB TerritoryCode = "SLB"
	SLE TerritoryCode = "SLE"
	SLV TerritoryCode = "SLV"
	SMR TerritoryCode = "SMR"
	SOM TerritoryCode = "SOM"
	SPM TerritoryCode = "SPM"
	SRB TerritoryCode = "SRB"
	SSD TerritoryCode = "SSD"
	STP TerritoryCode = "STP"
	SUR TerritoryCode = "SUR"
	SVK TerritoryCode = "SVK"
	SVN TerritoryCode = "SVN"
	SWE TerritoryCode = "SWE"
	SWZ TerritoryCode = "SWZ"
	SXM TerritoryCode = "SXM"
	SYC TerritoryCode = "SYC"
	TCA TerritoryCode = "TCA"
	TCD TerritoryCode = "TCD"
	TGO TerritoryCode = "TGO"
	THA TerritoryCode = "THA"
	TJK TerritoryCode = "TJK"
	TKM TerritoryCode = "TKM"
	TLS TerritoryCode = "TLS"
	TON TerritoryCode = "TON"
	TTO TerritoryCode = "TTO"
	TUN TerritoryCode = "TUN"
	TUR TerritoryCode = "TUR"
	TUV TerritoryCode = "TUV"
	TWN TerritoryCode = "TWN"
	TZA TerritoryCode = "TZA"
	UGA TerritoryCode = "UGA"
	UKR TerritoryCode = "UKR"
	UMI TerritoryCode = "UMI"
	URY TerritoryCode = "URY"
	USA TerritoryCode = "USA"
	UZB TerritoryCode = "UZB"
	VAT TerritoryCode = "VAT"
	VCT TerritoryCode = "VCT"
	VEN TerritoryCode = "VEN"
	VGB TerritoryCode = "VGB"
	VIR TerritoryCode = "VIR"
	VNM TerritoryCode = "VNM"
	VUT TerritoryCode = "VUT"
	WLF TerritoryCode = "WLF"
	WSM TerritoryCode = "WSM"
	YEM TerritoryCode = "YEM"
	ZAF TerritoryCode = "ZAF"
	ZMB TerritoryCode = "ZMB"
	ZWE TerritoryCode = "ZWE"
)

// All allowed values of TerritoryCode enum
var AllowedTerritoryCodeEnumValues = []TerritoryCode{
	"ABW",
	"AFG",
	"AGO",
	"AIA",
	"ALB",
	"AND",
	"ANT",
	"ARE",
	"ARG",
	"ARM",
	"ASM",
	"ATG",
	"AUS",
	"AUT",
	"AZE",
	"BDI",
	"BEL",
	"BEN",
	"BES",
	"BFA",
	"BGD",
	"BGR",
	"BHR",
	"BHS",
	"BIH",
	"BLR",
	"BLZ",
	"BMU",
	"BOL",
	"BRA",
	"BRB",
	"BRN",
	"BTN",
	"BWA",
	"CAF",
	"CAN",
	"CHE",
	"CHL",
	"CHN",
	"CIV",
	"CMR",
	"COD",
	"COG",
	"COK",
	"COL",
	"COM",
	"CPV",
	"CRI",
	"CUB",
	"CUW",
	"CXR",
	"CYM",
	"CYP",
	"CZE",
	"DEU",
	"DJI",
	"DMA",
	"DNK",
	"DOM",
	"DZA",
	"ECU",
	"EGY",
	"ERI",
	"ESP",
	"EST",
	"ETH",
	"FIN",
	"FJI",
	"FLK",
	"FRA",
	"FRO",
	"FSM",
	"GAB",
	"GBR",
	"GEO",
	"GGY",
	"GHA",
	"GIB",
	"GIN",
	"GLP",
	"GMB",
	"GNB",
	"GNQ",
	"GRC",
	"GRD",
	"GRL",
	"GTM",
	"GUF",
	"GUM",
	"GUY",
	"HKG",
	"HND",
	"HRV",
	"HTI",
	"HUN",
	"IDN",
	"IMN",
	"IND",
	"IRL",
	"IRQ",
	"ISL",
	"ISR",
	"ITA",
	"JAM",
	"JEY",
	"JOR",
	"JPN",
	"KAZ",
	"KEN",
	"KGZ",
	"KHM",
	"KIR",
	"KNA",
	"KOR",
	"KWT",
	"LAO",
	"LBN",
	"LBR",
	"LBY",
	"LCA",
	"LIE",
	"LKA",
	"LSO",
	"LTU",
	"LUX",
	"LVA",
	"MAC",
	"MAR",
	"MCO",
	"MDA",
	"MDG",
	"MDV",
	"MEX",
	"MHL",
	"MKD",
	"MLI",
	"MLT",
	"MMR",
	"MNE",
	"MNG",
	"MNP",
	"MOZ",
	"MRT",
	"MSR",
	"MTQ",
	"MUS",
	"MWI",
	"MYS",
	"MYT",
	"NAM",
	"NCL",
	"NER",
	"NFK",
	"NGA",
	"NIC",
	"NIU",
	"NLD",
	"NOR",
	"NPL",
	"NRU",
	"NZL",
	"OMN",
	"PAK",
	"PAN",
	"PER",
	"PHL",
	"PLW",
	"PNG",
	"POL",
	"PRI",
	"PRT",
	"PRY",
	"PSE",
	"PYF",
	"QAT",
	"REU",
	"ROU",
	"RUS",
	"RWA",
	"SAU",
	"SEN",
	"SGP",
	"SHN",
	"SLB",
	"SLE",
	"SLV",
	"SMR",
	"SOM",
	"SPM",
	"SRB",
	"SSD",
	"STP",
	"SUR",
	"SVK",
	"SVN",
	"SWE",
	"SWZ",
	"SXM",
	"SYC",
	"TCA",
	"TCD",
	"TGO",
	"THA",
	"TJK",
	"TKM",
	"TLS",
	"TON",
	"TTO",
	"TUN",
	"TUR",
	"TUV",
	"TWN",
	"TZA",
	"UGA",
	"UKR",
	"UMI",
	"URY",
	"USA",
	"UZB",
	"VAT",
	"VCT",
	"VEN",
	"VGB",
	"VIR",
	"VNM",
	"VUT",
	"WLF",
	"WSM",
	"YEM",
	"ZAF",
	"ZMB",
	"ZWE",
}

func (v *TerritoryCode) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := TerritoryCode(value)
	for _, existing := range AllowedTerritoryCodeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid TerritoryCode", value)
}

// NewTerritoryCodeFromValue returns a pointer to a valid TerritoryCode
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewTerritoryCodeFromValue(v string) (*TerritoryCode, error) {
	ev := TerritoryCode(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for TerritoryCode: valid values are %v", v, AllowedTerritoryCodeEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v TerritoryCode) IsValid() bool {
	for _, existing := range AllowedTerritoryCodeEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to TerritoryCode value
func (v TerritoryCode) Ptr() *TerritoryCode {
	return &v
}

type NullableTerritoryCode struct {
	value *TerritoryCode
	isSet bool
}

func (v NullableTerritoryCode) Get() *TerritoryCode {
	return v.value
}

func (v *NullableTerritoryCode) Set(val *TerritoryCode) {
	v.value = val
	v.isSet = true
}

func (v NullableTerritoryCode) IsSet() bool {
	return v.isSet
}

func (v *NullableTerritoryCode) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTerritoryCode(val *TerritoryCode) *NullableTerritoryCode {
	return &NullableTerritoryCode{value: val, isSet: true}
}

func (v NullableTerritoryCode) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTerritoryCode) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
