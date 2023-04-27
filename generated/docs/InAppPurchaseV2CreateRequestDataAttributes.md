# InAppPurchaseV2CreateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** |  | 
**ProductId** | **string** |  | 
**InAppPurchaseType** | [**InAppPurchaseType**](InAppPurchaseType.md) |  | 
**ReviewNote** | Pointer to **string** |  | [optional] 
**FamilySharable** | Pointer to **bool** |  | [optional] 
**AvailableInAllTerritories** | Pointer to **bool** |  | [optional] 

## Methods

### NewInAppPurchaseV2CreateRequestDataAttributes

`func NewInAppPurchaseV2CreateRequestDataAttributes(name string, productId string, inAppPurchaseType InAppPurchaseType, ) *InAppPurchaseV2CreateRequestDataAttributes`

NewInAppPurchaseV2CreateRequestDataAttributes instantiates a new InAppPurchaseV2CreateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseV2CreateRequestDataAttributesWithDefaults

`func NewInAppPurchaseV2CreateRequestDataAttributesWithDefaults() *InAppPurchaseV2CreateRequestDataAttributes`

NewInAppPurchaseV2CreateRequestDataAttributesWithDefaults instantiates a new InAppPurchaseV2CreateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *InAppPurchaseV2CreateRequestDataAttributes) SetName(v string)`

SetName sets Name field to given value.


### GetProductId

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetProductId() string`

GetProductId returns the ProductId field if non-nil, zero value otherwise.

### GetProductIdOk

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetProductIdOk() (*string, bool)`

GetProductIdOk returns a tuple with the ProductId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProductId

`func (o *InAppPurchaseV2CreateRequestDataAttributes) SetProductId(v string)`

SetProductId sets ProductId field to given value.


### GetInAppPurchaseType

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetInAppPurchaseType() InAppPurchaseType`

GetInAppPurchaseType returns the InAppPurchaseType field if non-nil, zero value otherwise.

### GetInAppPurchaseTypeOk

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetInAppPurchaseTypeOk() (*InAppPurchaseType, bool)`

GetInAppPurchaseTypeOk returns a tuple with the InAppPurchaseType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInAppPurchaseType

`func (o *InAppPurchaseV2CreateRequestDataAttributes) SetInAppPurchaseType(v InAppPurchaseType)`

SetInAppPurchaseType sets InAppPurchaseType field to given value.


### GetReviewNote

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetReviewNote() string`

GetReviewNote returns the ReviewNote field if non-nil, zero value otherwise.

### GetReviewNoteOk

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetReviewNoteOk() (*string, bool)`

GetReviewNoteOk returns a tuple with the ReviewNote field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReviewNote

`func (o *InAppPurchaseV2CreateRequestDataAttributes) SetReviewNote(v string)`

SetReviewNote sets ReviewNote field to given value.

### HasReviewNote

`func (o *InAppPurchaseV2CreateRequestDataAttributes) HasReviewNote() bool`

HasReviewNote returns a boolean if a field has been set.

### GetFamilySharable

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetFamilySharable() bool`

GetFamilySharable returns the FamilySharable field if non-nil, zero value otherwise.

### GetFamilySharableOk

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetFamilySharableOk() (*bool, bool)`

GetFamilySharableOk returns a tuple with the FamilySharable field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFamilySharable

`func (o *InAppPurchaseV2CreateRequestDataAttributes) SetFamilySharable(v bool)`

SetFamilySharable sets FamilySharable field to given value.

### HasFamilySharable

`func (o *InAppPurchaseV2CreateRequestDataAttributes) HasFamilySharable() bool`

HasFamilySharable returns a boolean if a field has been set.

### GetAvailableInAllTerritories

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetAvailableInAllTerritories() bool`

GetAvailableInAllTerritories returns the AvailableInAllTerritories field if non-nil, zero value otherwise.

### GetAvailableInAllTerritoriesOk

`func (o *InAppPurchaseV2CreateRequestDataAttributes) GetAvailableInAllTerritoriesOk() (*bool, bool)`

GetAvailableInAllTerritoriesOk returns a tuple with the AvailableInAllTerritories field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAvailableInAllTerritories

`func (o *InAppPurchaseV2CreateRequestDataAttributes) SetAvailableInAllTerritories(v bool)`

SetAvailableInAllTerritories sets AvailableInAllTerritories field to given value.

### HasAvailableInAllTerritories

`func (o *InAppPurchaseV2CreateRequestDataAttributes) HasAvailableInAllTerritories() bool`

HasAvailableInAllTerritories returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


