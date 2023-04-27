# InAppPurchaseContent

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**InAppPurchaseContentAttributes**](InAppPurchaseContentAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchaseAppStoreReviewScreenshotRelationships**](InAppPurchaseAppStoreReviewScreenshotRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchaseContent

`func NewInAppPurchaseContent(type_ string, id string, links ResourceLinks, ) *InAppPurchaseContent`

NewInAppPurchaseContent instantiates a new InAppPurchaseContent object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseContentWithDefaults

`func NewInAppPurchaseContentWithDefaults() *InAppPurchaseContent`

NewInAppPurchaseContentWithDefaults instantiates a new InAppPurchaseContent object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchaseContent) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchaseContent) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchaseContent) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchaseContent) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchaseContent) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchaseContent) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *InAppPurchaseContent) GetAttributes() InAppPurchaseContentAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchaseContent) GetAttributesOk() (*InAppPurchaseContentAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchaseContent) SetAttributes(v InAppPurchaseContentAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *InAppPurchaseContent) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *InAppPurchaseContent) GetRelationships() InAppPurchaseAppStoreReviewScreenshotRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchaseContent) GetRelationshipsOk() (*InAppPurchaseAppStoreReviewScreenshotRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchaseContent) SetRelationships(v InAppPurchaseAppStoreReviewScreenshotRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchaseContent) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseContent) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseContent) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseContent) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


