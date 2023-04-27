# InAppPurchaseLocalization

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**InAppPurchaseLocalizationAttributes**](InAppPurchaseLocalizationAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchaseAppStoreReviewScreenshotRelationships**](InAppPurchaseAppStoreReviewScreenshotRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchaseLocalization

`func NewInAppPurchaseLocalization(type_ string, id string, links ResourceLinks, ) *InAppPurchaseLocalization`

NewInAppPurchaseLocalization instantiates a new InAppPurchaseLocalization object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseLocalizationWithDefaults

`func NewInAppPurchaseLocalizationWithDefaults() *InAppPurchaseLocalization`

NewInAppPurchaseLocalizationWithDefaults instantiates a new InAppPurchaseLocalization object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchaseLocalization) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchaseLocalization) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchaseLocalization) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchaseLocalization) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchaseLocalization) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchaseLocalization) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *InAppPurchaseLocalization) GetAttributes() InAppPurchaseLocalizationAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchaseLocalization) GetAttributesOk() (*InAppPurchaseLocalizationAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchaseLocalization) SetAttributes(v InAppPurchaseLocalizationAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *InAppPurchaseLocalization) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *InAppPurchaseLocalization) GetRelationships() InAppPurchaseAppStoreReviewScreenshotRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchaseLocalization) GetRelationshipsOk() (*InAppPurchaseAppStoreReviewScreenshotRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchaseLocalization) SetRelationships(v InAppPurchaseAppStoreReviewScreenshotRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchaseLocalization) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseLocalization) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseLocalization) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseLocalization) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


