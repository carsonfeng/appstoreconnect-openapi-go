# SandboxTesterV2UpdateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Territory** | Pointer to [**TerritoryCode**](TerritoryCode.md) |  | [optional] 
**InterruptPurchases** | Pointer to **bool** |  | [optional] 
**SubscriptionRenewalRate** | Pointer to **string** |  | [optional] 

## Methods

### NewSandboxTesterV2UpdateRequestDataAttributes

`func NewSandboxTesterV2UpdateRequestDataAttributes() *SandboxTesterV2UpdateRequestDataAttributes`

NewSandboxTesterV2UpdateRequestDataAttributes instantiates a new SandboxTesterV2UpdateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSandboxTesterV2UpdateRequestDataAttributesWithDefaults

`func NewSandboxTesterV2UpdateRequestDataAttributesWithDefaults() *SandboxTesterV2UpdateRequestDataAttributes`

NewSandboxTesterV2UpdateRequestDataAttributesWithDefaults instantiates a new SandboxTesterV2UpdateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTerritory

`func (o *SandboxTesterV2UpdateRequestDataAttributes) GetTerritory() TerritoryCode`

GetTerritory returns the Territory field if non-nil, zero value otherwise.

### GetTerritoryOk

`func (o *SandboxTesterV2UpdateRequestDataAttributes) GetTerritoryOk() (*TerritoryCode, bool)`

GetTerritoryOk returns a tuple with the Territory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTerritory

`func (o *SandboxTesterV2UpdateRequestDataAttributes) SetTerritory(v TerritoryCode)`

SetTerritory sets Territory field to given value.

### HasTerritory

`func (o *SandboxTesterV2UpdateRequestDataAttributes) HasTerritory() bool`

HasTerritory returns a boolean if a field has been set.

### GetInterruptPurchases

`func (o *SandboxTesterV2UpdateRequestDataAttributes) GetInterruptPurchases() bool`

GetInterruptPurchases returns the InterruptPurchases field if non-nil, zero value otherwise.

### GetInterruptPurchasesOk

`func (o *SandboxTesterV2UpdateRequestDataAttributes) GetInterruptPurchasesOk() (*bool, bool)`

GetInterruptPurchasesOk returns a tuple with the InterruptPurchases field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInterruptPurchases

`func (o *SandboxTesterV2UpdateRequestDataAttributes) SetInterruptPurchases(v bool)`

SetInterruptPurchases sets InterruptPurchases field to given value.

### HasInterruptPurchases

`func (o *SandboxTesterV2UpdateRequestDataAttributes) HasInterruptPurchases() bool`

HasInterruptPurchases returns a boolean if a field has been set.

### GetSubscriptionRenewalRate

`func (o *SandboxTesterV2UpdateRequestDataAttributes) GetSubscriptionRenewalRate() string`

GetSubscriptionRenewalRate returns the SubscriptionRenewalRate field if non-nil, zero value otherwise.

### GetSubscriptionRenewalRateOk

`func (o *SandboxTesterV2UpdateRequestDataAttributes) GetSubscriptionRenewalRateOk() (*string, bool)`

GetSubscriptionRenewalRateOk returns a tuple with the SubscriptionRenewalRate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubscriptionRenewalRate

`func (o *SandboxTesterV2UpdateRequestDataAttributes) SetSubscriptionRenewalRate(v string)`

SetSubscriptionRenewalRate sets SubscriptionRenewalRate field to given value.

### HasSubscriptionRenewalRate

`func (o *SandboxTesterV2UpdateRequestDataAttributes) HasSubscriptionRenewalRate() bool`

HasSubscriptionRenewalRate returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


