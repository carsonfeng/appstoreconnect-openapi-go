# SubscriptionLocalization

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**InAppPurchaseLocalizationAttributes**](InAppPurchaseLocalizationAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionAppStoreReviewScreenshotRelationships**](SubscriptionAppStoreReviewScreenshotRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionLocalization

`func NewSubscriptionLocalization(type_ string, id string, links ResourceLinks, ) *SubscriptionLocalization`

NewSubscriptionLocalization instantiates a new SubscriptionLocalization object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionLocalizationWithDefaults

`func NewSubscriptionLocalizationWithDefaults() *SubscriptionLocalization`

NewSubscriptionLocalizationWithDefaults instantiates a new SubscriptionLocalization object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionLocalization) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionLocalization) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionLocalization) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionLocalization) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionLocalization) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionLocalization) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionLocalization) GetAttributes() InAppPurchaseLocalizationAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionLocalization) GetAttributesOk() (*InAppPurchaseLocalizationAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionLocalization) SetAttributes(v InAppPurchaseLocalizationAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionLocalization) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionLocalization) GetRelationships() SubscriptionAppStoreReviewScreenshotRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionLocalization) GetRelationshipsOk() (*SubscriptionAppStoreReviewScreenshotRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionLocalization) SetRelationships(v SubscriptionAppStoreReviewScreenshotRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionLocalization) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionLocalization) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionLocalization) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionLocalization) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


