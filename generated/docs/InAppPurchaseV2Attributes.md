# InAppPurchaseV2Attributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**ProductId** | Pointer to **string** |  | [optional] 
**InAppPurchaseType** | Pointer to [**InAppPurchaseType**](InAppPurchaseType.md) |  | [optional] 
**State** | Pointer to [**InAppPurchaseState**](InAppPurchaseState.md) |  | [optional] 
**ReviewNote** | Pointer to **string** |  | [optional] 
**FamilySharable** | Pointer to **bool** |  | [optional] 
**ContentHosting** | Pointer to **bool** |  | [optional] 
**AvailableInAllTerritories** | Pointer to **bool** |  | [optional] 

## Methods

### NewInAppPurchaseV2Attributes

`func NewInAppPurchaseV2Attributes() *InAppPurchaseV2Attributes`

NewInAppPurchaseV2Attributes instantiates a new InAppPurchaseV2Attributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseV2AttributesWithDefaults

`func NewInAppPurchaseV2AttributesWithDefaults() *InAppPurchaseV2Attributes`

NewInAppPurchaseV2AttributesWithDefaults instantiates a new InAppPurchaseV2Attributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *InAppPurchaseV2Attributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *InAppPurchaseV2Attributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *InAppPurchaseV2Attributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *InAppPurchaseV2Attributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetProductId

`func (o *InAppPurchaseV2Attributes) GetProductId() string`

GetProductId returns the ProductId field if non-nil, zero value otherwise.

### GetProductIdOk

`func (o *InAppPurchaseV2Attributes) GetProductIdOk() (*string, bool)`

GetProductIdOk returns a tuple with the ProductId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProductId

`func (o *InAppPurchaseV2Attributes) SetProductId(v string)`

SetProductId sets ProductId field to given value.

### HasProductId

`func (o *InAppPurchaseV2Attributes) HasProductId() bool`

HasProductId returns a boolean if a field has been set.

### GetInAppPurchaseType

`func (o *InAppPurchaseV2Attributes) GetInAppPurchaseType() InAppPurchaseType`

GetInAppPurchaseType returns the InAppPurchaseType field if non-nil, zero value otherwise.

### GetInAppPurchaseTypeOk

`func (o *InAppPurchaseV2Attributes) GetInAppPurchaseTypeOk() (*InAppPurchaseType, bool)`

GetInAppPurchaseTypeOk returns a tuple with the InAppPurchaseType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInAppPurchaseType

`func (o *InAppPurchaseV2Attributes) SetInAppPurchaseType(v InAppPurchaseType)`

SetInAppPurchaseType sets InAppPurchaseType field to given value.

### HasInAppPurchaseType

`func (o *InAppPurchaseV2Attributes) HasInAppPurchaseType() bool`

HasInAppPurchaseType returns a boolean if a field has been set.

### GetState

`func (o *InAppPurchaseV2Attributes) GetState() InAppPurchaseState`

GetState returns the State field if non-nil, zero value otherwise.

### GetStateOk

`func (o *InAppPurchaseV2Attributes) GetStateOk() (*InAppPurchaseState, bool)`

GetStateOk returns a tuple with the State field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetState

`func (o *InAppPurchaseV2Attributes) SetState(v InAppPurchaseState)`

SetState sets State field to given value.

### HasState

`func (o *InAppPurchaseV2Attributes) HasState() bool`

HasState returns a boolean if a field has been set.

### GetReviewNote

`func (o *InAppPurchaseV2Attributes) GetReviewNote() string`

GetReviewNote returns the ReviewNote field if non-nil, zero value otherwise.

### GetReviewNoteOk

`func (o *InAppPurchaseV2Attributes) GetReviewNoteOk() (*string, bool)`

GetReviewNoteOk returns a tuple with the ReviewNote field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReviewNote

`func (o *InAppPurchaseV2Attributes) SetReviewNote(v string)`

SetReviewNote sets ReviewNote field to given value.

### HasReviewNote

`func (o *InAppPurchaseV2Attributes) HasReviewNote() bool`

HasReviewNote returns a boolean if a field has been set.

### GetFamilySharable

`func (o *InAppPurchaseV2Attributes) GetFamilySharable() bool`

GetFamilySharable returns the FamilySharable field if non-nil, zero value otherwise.

### GetFamilySharableOk

`func (o *InAppPurchaseV2Attributes) GetFamilySharableOk() (*bool, bool)`

GetFamilySharableOk returns a tuple with the FamilySharable field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFamilySharable

`func (o *InAppPurchaseV2Attributes) SetFamilySharable(v bool)`

SetFamilySharable sets FamilySharable field to given value.

### HasFamilySharable

`func (o *InAppPurchaseV2Attributes) HasFamilySharable() bool`

HasFamilySharable returns a boolean if a field has been set.

### GetContentHosting

`func (o *InAppPurchaseV2Attributes) GetContentHosting() bool`

GetContentHosting returns the ContentHosting field if non-nil, zero value otherwise.

### GetContentHostingOk

`func (o *InAppPurchaseV2Attributes) GetContentHostingOk() (*bool, bool)`

GetContentHostingOk returns a tuple with the ContentHosting field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetContentHosting

`func (o *InAppPurchaseV2Attributes) SetContentHosting(v bool)`

SetContentHosting sets ContentHosting field to given value.

### HasContentHosting

`func (o *InAppPurchaseV2Attributes) HasContentHosting() bool`

HasContentHosting returns a boolean if a field has been set.

### GetAvailableInAllTerritories

`func (o *InAppPurchaseV2Attributes) GetAvailableInAllTerritories() bool`

GetAvailableInAllTerritories returns the AvailableInAllTerritories field if non-nil, zero value otherwise.

### GetAvailableInAllTerritoriesOk

`func (o *InAppPurchaseV2Attributes) GetAvailableInAllTerritoriesOk() (*bool, bool)`

GetAvailableInAllTerritoriesOk returns a tuple with the AvailableInAllTerritories field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAvailableInAllTerritories

`func (o *InAppPurchaseV2Attributes) SetAvailableInAllTerritories(v bool)`

SetAvailableInAllTerritories sets AvailableInAllTerritories field to given value.

### HasAvailableInAllTerritories

`func (o *InAppPurchaseV2Attributes) HasAvailableInAllTerritories() bool`

HasAvailableInAllTerritories returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


