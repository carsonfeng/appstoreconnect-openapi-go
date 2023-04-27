# CustomerReview

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CustomerReviewAttributes**](CustomerReviewAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**CustomerReviewRelationships**](CustomerReviewRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCustomerReview

`func NewCustomerReview(type_ string, id string, links ResourceLinks, ) *CustomerReview`

NewCustomerReview instantiates a new CustomerReview object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCustomerReviewWithDefaults

`func NewCustomerReviewWithDefaults() *CustomerReview`

NewCustomerReviewWithDefaults instantiates a new CustomerReview object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CustomerReview) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CustomerReview) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CustomerReview) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CustomerReview) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CustomerReview) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CustomerReview) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CustomerReview) GetAttributes() CustomerReviewAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CustomerReview) GetAttributesOk() (*CustomerReviewAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CustomerReview) SetAttributes(v CustomerReviewAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CustomerReview) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CustomerReview) GetRelationships() CustomerReviewRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CustomerReview) GetRelationshipsOk() (*CustomerReviewRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CustomerReview) SetRelationships(v CustomerReviewRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CustomerReview) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *CustomerReview) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CustomerReview) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CustomerReview) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


