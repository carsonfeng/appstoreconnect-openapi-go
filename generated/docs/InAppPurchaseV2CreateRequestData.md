# InAppPurchaseV2CreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | [**InAppPurchaseV2CreateRequestDataAttributes**](InAppPurchaseV2CreateRequestDataAttributes.md) |  | 
**Relationships** | [**AppEventCreateRequestDataRelationships**](AppEventCreateRequestDataRelationships.md) |  | 

## Methods

### NewInAppPurchaseV2CreateRequestData

`func NewInAppPurchaseV2CreateRequestData(type_ string, attributes InAppPurchaseV2CreateRequestDataAttributes, relationships AppEventCreateRequestDataRelationships, ) *InAppPurchaseV2CreateRequestData`

NewInAppPurchaseV2CreateRequestData instantiates a new InAppPurchaseV2CreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseV2CreateRequestDataWithDefaults

`func NewInAppPurchaseV2CreateRequestDataWithDefaults() *InAppPurchaseV2CreateRequestData`

NewInAppPurchaseV2CreateRequestDataWithDefaults instantiates a new InAppPurchaseV2CreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchaseV2CreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchaseV2CreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchaseV2CreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *InAppPurchaseV2CreateRequestData) GetAttributes() InAppPurchaseV2CreateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchaseV2CreateRequestData) GetAttributesOk() (*InAppPurchaseV2CreateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchaseV2CreateRequestData) SetAttributes(v InAppPurchaseV2CreateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *InAppPurchaseV2CreateRequestData) GetRelationships() AppEventCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchaseV2CreateRequestData) GetRelationshipsOk() (*AppEventCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchaseV2CreateRequestData) SetRelationships(v AppEventCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


