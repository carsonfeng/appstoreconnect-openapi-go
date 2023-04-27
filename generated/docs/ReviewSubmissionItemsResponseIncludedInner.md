# ReviewSubmissionItemsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppEventAttributes**](AppEventAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppEventRelationships**](AppEventRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewReviewSubmissionItemsResponseIncludedInner

`func NewReviewSubmissionItemsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *ReviewSubmissionItemsResponseIncludedInner`

NewReviewSubmissionItemsResponseIncludedInner instantiates a new ReviewSubmissionItemsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionItemsResponseIncludedInnerWithDefaults

`func NewReviewSubmissionItemsResponseIncludedInnerWithDefaults() *ReviewSubmissionItemsResponseIncludedInner`

NewReviewSubmissionItemsResponseIncludedInnerWithDefaults instantiates a new ReviewSubmissionItemsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ReviewSubmissionItemsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *ReviewSubmissionItemsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetAttributes() AppEventAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetAttributesOk() (*AppEventAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *ReviewSubmissionItemsResponseIncludedInner) SetAttributes(v AppEventAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *ReviewSubmissionItemsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetRelationships() AppEventRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetRelationshipsOk() (*AppEventRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *ReviewSubmissionItemsResponseIncludedInner) SetRelationships(v AppEventRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *ReviewSubmissionItemsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ReviewSubmissionItemsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ReviewSubmissionItemsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


