# SubscriptionSubmission

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Relationships** | Pointer to [**SubscriptionAppStoreReviewScreenshotRelationships**](SubscriptionAppStoreReviewScreenshotRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionSubmission

`func NewSubscriptionSubmission(type_ string, id string, links ResourceLinks, ) *SubscriptionSubmission`

NewSubscriptionSubmission instantiates a new SubscriptionSubmission object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionSubmissionWithDefaults

`func NewSubscriptionSubmissionWithDefaults() *SubscriptionSubmission`

NewSubscriptionSubmissionWithDefaults instantiates a new SubscriptionSubmission object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionSubmission) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionSubmission) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionSubmission) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionSubmission) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionSubmission) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionSubmission) SetId(v string)`

SetId sets Id field to given value.


### GetRelationships

`func (o *SubscriptionSubmission) GetRelationships() SubscriptionAppStoreReviewScreenshotRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionSubmission) GetRelationshipsOk() (*SubscriptionAppStoreReviewScreenshotRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionSubmission) SetRelationships(v SubscriptionAppStoreReviewScreenshotRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionSubmission) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionSubmission) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionSubmission) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionSubmission) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


