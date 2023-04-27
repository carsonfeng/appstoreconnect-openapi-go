# InAppPurchaseSubmission

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Relationships** | Pointer to [**InAppPurchaseAppStoreReviewScreenshotRelationships**](InAppPurchaseAppStoreReviewScreenshotRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchaseSubmission

`func NewInAppPurchaseSubmission(type_ string, id string, links ResourceLinks, ) *InAppPurchaseSubmission`

NewInAppPurchaseSubmission instantiates a new InAppPurchaseSubmission object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseSubmissionWithDefaults

`func NewInAppPurchaseSubmissionWithDefaults() *InAppPurchaseSubmission`

NewInAppPurchaseSubmissionWithDefaults instantiates a new InAppPurchaseSubmission object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchaseSubmission) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchaseSubmission) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchaseSubmission) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchaseSubmission) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchaseSubmission) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchaseSubmission) SetId(v string)`

SetId sets Id field to given value.


### GetRelationships

`func (o *InAppPurchaseSubmission) GetRelationships() InAppPurchaseAppStoreReviewScreenshotRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchaseSubmission) GetRelationshipsOk() (*InAppPurchaseAppStoreReviewScreenshotRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchaseSubmission) SetRelationships(v InAppPurchaseAppStoreReviewScreenshotRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchaseSubmission) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseSubmission) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseSubmission) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseSubmission) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


