# ReviewSubmission

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**ReviewSubmissionAttributes**](ReviewSubmissionAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**ReviewSubmissionRelationships**](ReviewSubmissionRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewReviewSubmission

`func NewReviewSubmission(type_ string, id string, links ResourceLinks, ) *ReviewSubmission`

NewReviewSubmission instantiates a new ReviewSubmission object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionWithDefaults

`func NewReviewSubmissionWithDefaults() *ReviewSubmission`

NewReviewSubmissionWithDefaults instantiates a new ReviewSubmission object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *ReviewSubmission) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ReviewSubmission) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ReviewSubmission) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *ReviewSubmission) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *ReviewSubmission) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *ReviewSubmission) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *ReviewSubmission) GetAttributes() ReviewSubmissionAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *ReviewSubmission) GetAttributesOk() (*ReviewSubmissionAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *ReviewSubmission) SetAttributes(v ReviewSubmissionAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *ReviewSubmission) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *ReviewSubmission) GetRelationships() ReviewSubmissionRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *ReviewSubmission) GetRelationshipsOk() (*ReviewSubmissionRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *ReviewSubmission) SetRelationships(v ReviewSubmissionRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *ReviewSubmission) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *ReviewSubmission) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ReviewSubmission) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ReviewSubmission) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


