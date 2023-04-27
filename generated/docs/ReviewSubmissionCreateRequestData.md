# ReviewSubmissionCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | [**ReviewSubmissionCreateRequestDataAttributes**](ReviewSubmissionCreateRequestDataAttributes.md) |  | 
**Relationships** | [**AppEventCreateRequestDataRelationships**](AppEventCreateRequestDataRelationships.md) |  | 

## Methods

### NewReviewSubmissionCreateRequestData

`func NewReviewSubmissionCreateRequestData(type_ string, attributes ReviewSubmissionCreateRequestDataAttributes, relationships AppEventCreateRequestDataRelationships, ) *ReviewSubmissionCreateRequestData`

NewReviewSubmissionCreateRequestData instantiates a new ReviewSubmissionCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionCreateRequestDataWithDefaults

`func NewReviewSubmissionCreateRequestDataWithDefaults() *ReviewSubmissionCreateRequestData`

NewReviewSubmissionCreateRequestDataWithDefaults instantiates a new ReviewSubmissionCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *ReviewSubmissionCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ReviewSubmissionCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ReviewSubmissionCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *ReviewSubmissionCreateRequestData) GetAttributes() ReviewSubmissionCreateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *ReviewSubmissionCreateRequestData) GetAttributesOk() (*ReviewSubmissionCreateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *ReviewSubmissionCreateRequestData) SetAttributes(v ReviewSubmissionCreateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *ReviewSubmissionCreateRequestData) GetRelationships() AppEventCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *ReviewSubmissionCreateRequestData) GetRelationshipsOk() (*AppEventCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *ReviewSubmissionCreateRequestData) SetRelationships(v AppEventCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


