# BuildBundleAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**BundleId** | Pointer to **string** |  | [optional] 
**BundleType** | Pointer to **string** |  | [optional] 
**SdkBuild** | Pointer to **string** |  | [optional] 
**PlatformBuild** | Pointer to **string** |  | [optional] 
**FileName** | Pointer to **string** |  | [optional] 
**HasSirikit** | Pointer to **bool** |  | [optional] 
**HasOnDemandResources** | Pointer to **bool** |  | [optional] 
**HasPrerenderedIcon** | Pointer to **bool** |  | [optional] 
**UsesLocationServices** | Pointer to **bool** |  | [optional] 
**IsIosBuildMacAppStoreCompatible** | Pointer to **bool** |  | [optional] 
**IncludesSymbols** | Pointer to **bool** |  | [optional] 
**DSYMUrl** | Pointer to **string** |  | [optional] 
**SupportedArchitectures** | Pointer to **[]string** |  | [optional] 
**RequiredCapabilities** | Pointer to **[]string** |  | [optional] 
**DeviceProtocols** | Pointer to **[]string** |  | [optional] 
**Locales** | Pointer to **[]string** |  | [optional] 
**Entitlements** | Pointer to **map[string]map[string]string** |  | [optional] 

## Methods

### NewBuildBundleAttributes

`func NewBuildBundleAttributes() *BuildBundleAttributes`

NewBuildBundleAttributes instantiates a new BuildBundleAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBuildBundleAttributesWithDefaults

`func NewBuildBundleAttributesWithDefaults() *BuildBundleAttributes`

NewBuildBundleAttributesWithDefaults instantiates a new BuildBundleAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetBundleId

`func (o *BuildBundleAttributes) GetBundleId() string`

GetBundleId returns the BundleId field if non-nil, zero value otherwise.

### GetBundleIdOk

`func (o *BuildBundleAttributes) GetBundleIdOk() (*string, bool)`

GetBundleIdOk returns a tuple with the BundleId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBundleId

`func (o *BuildBundleAttributes) SetBundleId(v string)`

SetBundleId sets BundleId field to given value.

### HasBundleId

`func (o *BuildBundleAttributes) HasBundleId() bool`

HasBundleId returns a boolean if a field has been set.

### GetBundleType

`func (o *BuildBundleAttributes) GetBundleType() string`

GetBundleType returns the BundleType field if non-nil, zero value otherwise.

### GetBundleTypeOk

`func (o *BuildBundleAttributes) GetBundleTypeOk() (*string, bool)`

GetBundleTypeOk returns a tuple with the BundleType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBundleType

`func (o *BuildBundleAttributes) SetBundleType(v string)`

SetBundleType sets BundleType field to given value.

### HasBundleType

`func (o *BuildBundleAttributes) HasBundleType() bool`

HasBundleType returns a boolean if a field has been set.

### GetSdkBuild

`func (o *BuildBundleAttributes) GetSdkBuild() string`

GetSdkBuild returns the SdkBuild field if non-nil, zero value otherwise.

### GetSdkBuildOk

`func (o *BuildBundleAttributes) GetSdkBuildOk() (*string, bool)`

GetSdkBuildOk returns a tuple with the SdkBuild field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSdkBuild

`func (o *BuildBundleAttributes) SetSdkBuild(v string)`

SetSdkBuild sets SdkBuild field to given value.

### HasSdkBuild

`func (o *BuildBundleAttributes) HasSdkBuild() bool`

HasSdkBuild returns a boolean if a field has been set.

### GetPlatformBuild

`func (o *BuildBundleAttributes) GetPlatformBuild() string`

GetPlatformBuild returns the PlatformBuild field if non-nil, zero value otherwise.

### GetPlatformBuildOk

`func (o *BuildBundleAttributes) GetPlatformBuildOk() (*string, bool)`

GetPlatformBuildOk returns a tuple with the PlatformBuild field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPlatformBuild

`func (o *BuildBundleAttributes) SetPlatformBuild(v string)`

SetPlatformBuild sets PlatformBuild field to given value.

### HasPlatformBuild

`func (o *BuildBundleAttributes) HasPlatformBuild() bool`

HasPlatformBuild returns a boolean if a field has been set.

### GetFileName

`func (o *BuildBundleAttributes) GetFileName() string`

GetFileName returns the FileName field if non-nil, zero value otherwise.

### GetFileNameOk

`func (o *BuildBundleAttributes) GetFileNameOk() (*string, bool)`

GetFileNameOk returns a tuple with the FileName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileName

`func (o *BuildBundleAttributes) SetFileName(v string)`

SetFileName sets FileName field to given value.

### HasFileName

`func (o *BuildBundleAttributes) HasFileName() bool`

HasFileName returns a boolean if a field has been set.

### GetHasSirikit

`func (o *BuildBundleAttributes) GetHasSirikit() bool`

GetHasSirikit returns the HasSirikit field if non-nil, zero value otherwise.

### GetHasSirikitOk

`func (o *BuildBundleAttributes) GetHasSirikitOk() (*bool, bool)`

GetHasSirikitOk returns a tuple with the HasSirikit field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHasSirikit

`func (o *BuildBundleAttributes) SetHasSirikit(v bool)`

SetHasSirikit sets HasSirikit field to given value.

### HasHasSirikit

`func (o *BuildBundleAttributes) HasHasSirikit() bool`

HasHasSirikit returns a boolean if a field has been set.

### GetHasOnDemandResources

`func (o *BuildBundleAttributes) GetHasOnDemandResources() bool`

GetHasOnDemandResources returns the HasOnDemandResources field if non-nil, zero value otherwise.

### GetHasOnDemandResourcesOk

`func (o *BuildBundleAttributes) GetHasOnDemandResourcesOk() (*bool, bool)`

GetHasOnDemandResourcesOk returns a tuple with the HasOnDemandResources field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHasOnDemandResources

`func (o *BuildBundleAttributes) SetHasOnDemandResources(v bool)`

SetHasOnDemandResources sets HasOnDemandResources field to given value.

### HasHasOnDemandResources

`func (o *BuildBundleAttributes) HasHasOnDemandResources() bool`

HasHasOnDemandResources returns a boolean if a field has been set.

### GetHasPrerenderedIcon

`func (o *BuildBundleAttributes) GetHasPrerenderedIcon() bool`

GetHasPrerenderedIcon returns the HasPrerenderedIcon field if non-nil, zero value otherwise.

### GetHasPrerenderedIconOk

`func (o *BuildBundleAttributes) GetHasPrerenderedIconOk() (*bool, bool)`

GetHasPrerenderedIconOk returns a tuple with the HasPrerenderedIcon field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHasPrerenderedIcon

`func (o *BuildBundleAttributes) SetHasPrerenderedIcon(v bool)`

SetHasPrerenderedIcon sets HasPrerenderedIcon field to given value.

### HasHasPrerenderedIcon

`func (o *BuildBundleAttributes) HasHasPrerenderedIcon() bool`

HasHasPrerenderedIcon returns a boolean if a field has been set.

### GetUsesLocationServices

`func (o *BuildBundleAttributes) GetUsesLocationServices() bool`

GetUsesLocationServices returns the UsesLocationServices field if non-nil, zero value otherwise.

### GetUsesLocationServicesOk

`func (o *BuildBundleAttributes) GetUsesLocationServicesOk() (*bool, bool)`

GetUsesLocationServicesOk returns a tuple with the UsesLocationServices field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUsesLocationServices

`func (o *BuildBundleAttributes) SetUsesLocationServices(v bool)`

SetUsesLocationServices sets UsesLocationServices field to given value.

### HasUsesLocationServices

`func (o *BuildBundleAttributes) HasUsesLocationServices() bool`

HasUsesLocationServices returns a boolean if a field has been set.

### GetIsIosBuildMacAppStoreCompatible

`func (o *BuildBundleAttributes) GetIsIosBuildMacAppStoreCompatible() bool`

GetIsIosBuildMacAppStoreCompatible returns the IsIosBuildMacAppStoreCompatible field if non-nil, zero value otherwise.

### GetIsIosBuildMacAppStoreCompatibleOk

`func (o *BuildBundleAttributes) GetIsIosBuildMacAppStoreCompatibleOk() (*bool, bool)`

GetIsIosBuildMacAppStoreCompatibleOk returns a tuple with the IsIosBuildMacAppStoreCompatible field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsIosBuildMacAppStoreCompatible

`func (o *BuildBundleAttributes) SetIsIosBuildMacAppStoreCompatible(v bool)`

SetIsIosBuildMacAppStoreCompatible sets IsIosBuildMacAppStoreCompatible field to given value.

### HasIsIosBuildMacAppStoreCompatible

`func (o *BuildBundleAttributes) HasIsIosBuildMacAppStoreCompatible() bool`

HasIsIosBuildMacAppStoreCompatible returns a boolean if a field has been set.

### GetIncludesSymbols

`func (o *BuildBundleAttributes) GetIncludesSymbols() bool`

GetIncludesSymbols returns the IncludesSymbols field if non-nil, zero value otherwise.

### GetIncludesSymbolsOk

`func (o *BuildBundleAttributes) GetIncludesSymbolsOk() (*bool, bool)`

GetIncludesSymbolsOk returns a tuple with the IncludesSymbols field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncludesSymbols

`func (o *BuildBundleAttributes) SetIncludesSymbols(v bool)`

SetIncludesSymbols sets IncludesSymbols field to given value.

### HasIncludesSymbols

`func (o *BuildBundleAttributes) HasIncludesSymbols() bool`

HasIncludesSymbols returns a boolean if a field has been set.

### GetDSYMUrl

`func (o *BuildBundleAttributes) GetDSYMUrl() string`

GetDSYMUrl returns the DSYMUrl field if non-nil, zero value otherwise.

### GetDSYMUrlOk

`func (o *BuildBundleAttributes) GetDSYMUrlOk() (*string, bool)`

GetDSYMUrlOk returns a tuple with the DSYMUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDSYMUrl

`func (o *BuildBundleAttributes) SetDSYMUrl(v string)`

SetDSYMUrl sets DSYMUrl field to given value.

### HasDSYMUrl

`func (o *BuildBundleAttributes) HasDSYMUrl() bool`

HasDSYMUrl returns a boolean if a field has been set.

### GetSupportedArchitectures

`func (o *BuildBundleAttributes) GetSupportedArchitectures() []string`

GetSupportedArchitectures returns the SupportedArchitectures field if non-nil, zero value otherwise.

### GetSupportedArchitecturesOk

`func (o *BuildBundleAttributes) GetSupportedArchitecturesOk() (*[]string, bool)`

GetSupportedArchitecturesOk returns a tuple with the SupportedArchitectures field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSupportedArchitectures

`func (o *BuildBundleAttributes) SetSupportedArchitectures(v []string)`

SetSupportedArchitectures sets SupportedArchitectures field to given value.

### HasSupportedArchitectures

`func (o *BuildBundleAttributes) HasSupportedArchitectures() bool`

HasSupportedArchitectures returns a boolean if a field has been set.

### GetRequiredCapabilities

`func (o *BuildBundleAttributes) GetRequiredCapabilities() []string`

GetRequiredCapabilities returns the RequiredCapabilities field if non-nil, zero value otherwise.

### GetRequiredCapabilitiesOk

`func (o *BuildBundleAttributes) GetRequiredCapabilitiesOk() (*[]string, bool)`

GetRequiredCapabilitiesOk returns a tuple with the RequiredCapabilities field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequiredCapabilities

`func (o *BuildBundleAttributes) SetRequiredCapabilities(v []string)`

SetRequiredCapabilities sets RequiredCapabilities field to given value.

### HasRequiredCapabilities

`func (o *BuildBundleAttributes) HasRequiredCapabilities() bool`

HasRequiredCapabilities returns a boolean if a field has been set.

### GetDeviceProtocols

`func (o *BuildBundleAttributes) GetDeviceProtocols() []string`

GetDeviceProtocols returns the DeviceProtocols field if non-nil, zero value otherwise.

### GetDeviceProtocolsOk

`func (o *BuildBundleAttributes) GetDeviceProtocolsOk() (*[]string, bool)`

GetDeviceProtocolsOk returns a tuple with the DeviceProtocols field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDeviceProtocols

`func (o *BuildBundleAttributes) SetDeviceProtocols(v []string)`

SetDeviceProtocols sets DeviceProtocols field to given value.

### HasDeviceProtocols

`func (o *BuildBundleAttributes) HasDeviceProtocols() bool`

HasDeviceProtocols returns a boolean if a field has been set.

### GetLocales

`func (o *BuildBundleAttributes) GetLocales() []string`

GetLocales returns the Locales field if non-nil, zero value otherwise.

### GetLocalesOk

`func (o *BuildBundleAttributes) GetLocalesOk() (*[]string, bool)`

GetLocalesOk returns a tuple with the Locales field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLocales

`func (o *BuildBundleAttributes) SetLocales(v []string)`

SetLocales sets Locales field to given value.

### HasLocales

`func (o *BuildBundleAttributes) HasLocales() bool`

HasLocales returns a boolean if a field has been set.

### GetEntitlements

`func (o *BuildBundleAttributes) GetEntitlements() map[string]map[string]string`

GetEntitlements returns the Entitlements field if non-nil, zero value otherwise.

### GetEntitlementsOk

`func (o *BuildBundleAttributes) GetEntitlementsOk() (*map[string]map[string]string, bool)`

GetEntitlementsOk returns a tuple with the Entitlements field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEntitlements

`func (o *BuildBundleAttributes) SetEntitlements(v map[string]map[string]string)`

SetEntitlements sets Entitlements field to given value.

### HasEntitlements

`func (o *BuildBundleAttributes) HasEntitlements() bool`

HasEntitlements returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


