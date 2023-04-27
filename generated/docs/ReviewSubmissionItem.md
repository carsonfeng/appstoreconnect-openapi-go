# ReviewSubmissionItem

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**ReviewSubmissionItemAttributes**](ReviewSubmissionItemAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**ReviewSubmissionItemRelationships**](ReviewSubmissionItemRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewReviewSubmissionItem

`func NewReviewSubmissionItem(type_ string, id string, links ResourceLinks, ) *ReviewSubmissionItem`

NewReviewSubmissionItem instantiates a new ReviewSubmissionItem object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionItemWithDefaults

`func NewReviewSubmissionItemWithDefaults() *ReviewSubmissionItem`

NewReviewSubmissionItemWithDefaults instantiates a new ReviewSubmissionItem object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *ReviewSubmissionItem) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ReviewSubmissionItem) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ReviewSubmissionItem) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *ReviewSubmissionItem) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *ReviewSubmissionItem) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *ReviewSubmissionItem) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *ReviewSubmissionItem) GetAttributes() ReviewSubmissionItemAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *ReviewSubmissionItem) GetAttributesOk() (*ReviewSubmissionItemAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *ReviewSubmissionItem) SetAttributes(v ReviewSubmissionItemAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *ReviewSubmissionItem) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *ReviewSubmissionItem) GetRelationships() ReviewSubmissionItemRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *ReviewSubmissionItem) GetRelationshipsOk() (*ReviewSubmissionItemRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *ReviewSubmissionItem) SetRelationships(v ReviewSubmissionItemRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *ReviewSubmissionItem) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *ReviewSubmissionItem) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ReviewSubmissionItem) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ReviewSubmissionItem) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


