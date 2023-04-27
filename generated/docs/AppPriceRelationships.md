# AppPriceRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**App** | Pointer to [**AppAvailabilityRelationshipsApp**](AppAvailabilityRelationshipsApp.md) |  | [optional] 
**PriceTier** | Pointer to [**AppPricePointV2RelationshipsPriceTier**](AppPricePointV2RelationshipsPriceTier.md) |  | [optional] 

## Methods

### NewAppPriceRelationships

`func NewAppPriceRelationships() *AppPriceRelationships`

NewAppPriceRelationships instantiates a new AppPriceRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPriceRelationshipsWithDefaults

`func NewAppPriceRelationshipsWithDefaults() *AppPriceRelationships`

NewAppPriceRelationshipsWithDefaults instantiates a new AppPriceRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetApp

`func (o *AppPriceRelationships) GetApp() AppAvailabilityRelationshipsApp`

GetApp returns the App field if non-nil, zero value otherwise.

### GetAppOk

`func (o *AppPriceRelationships) GetAppOk() (*AppAvailabilityRelationshipsApp, bool)`

GetAppOk returns a tuple with the App field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetApp

`func (o *AppPriceRelationships) SetApp(v AppAvailabilityRelationshipsApp)`

SetApp sets App field to given value.

### HasApp

`func (o *AppPriceRelationships) HasApp() bool`

HasApp returns a boolean if a field has been set.

### GetPriceTier

`func (o *AppPriceRelationships) GetPriceTier() AppPricePointV2RelationshipsPriceTier`

GetPriceTier returns the PriceTier field if non-nil, zero value otherwise.

### GetPriceTierOk

`func (o *AppPriceRelationships) GetPriceTierOk() (*AppPricePointV2RelationshipsPriceTier, bool)`

GetPriceTierOk returns a tuple with the PriceTier field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPriceTier

`func (o *AppPriceRelationships) SetPriceTier(v AppPricePointV2RelationshipsPriceTier)`

SetPriceTier sets PriceTier field to given value.

### HasPriceTier

`func (o *AppPriceRelationships) HasPriceTier() bool`

HasPriceTier returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


