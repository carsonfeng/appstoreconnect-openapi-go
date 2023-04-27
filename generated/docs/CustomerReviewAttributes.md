# CustomerReviewAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Rating** | Pointer to **int32** |  | [optional] 
**Title** | Pointer to **string** |  | [optional] 
**Body** | Pointer to **string** |  | [optional] 
**ReviewerNickname** | Pointer to **string** |  | [optional] 
**CreatedDate** | Pointer to **time.Time** |  | [optional] 
**Territory** | Pointer to [**TerritoryCode**](TerritoryCode.md) |  | [optional] 

## Methods

### NewCustomerReviewAttributes

`func NewCustomerReviewAttributes() *CustomerReviewAttributes`

NewCustomerReviewAttributes instantiates a new CustomerReviewAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCustomerReviewAttributesWithDefaults

`func NewCustomerReviewAttributesWithDefaults() *CustomerReviewAttributes`

NewCustomerReviewAttributesWithDefaults instantiates a new CustomerReviewAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRating

`func (o *CustomerReviewAttributes) GetRating() int32`

GetRating returns the Rating field if non-nil, zero value otherwise.

### GetRatingOk

`func (o *CustomerReviewAttributes) GetRatingOk() (*int32, bool)`

GetRatingOk returns a tuple with the Rating field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRating

`func (o *CustomerReviewAttributes) SetRating(v int32)`

SetRating sets Rating field to given value.

### HasRating

`func (o *CustomerReviewAttributes) HasRating() bool`

HasRating returns a boolean if a field has been set.

### GetTitle

`func (o *CustomerReviewAttributes) GetTitle() string`

GetTitle returns the Title field if non-nil, zero value otherwise.

### GetTitleOk

`func (o *CustomerReviewAttributes) GetTitleOk() (*string, bool)`

GetTitleOk returns a tuple with the Title field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTitle

`func (o *CustomerReviewAttributes) SetTitle(v string)`

SetTitle sets Title field to given value.

### HasTitle

`func (o *CustomerReviewAttributes) HasTitle() bool`

HasTitle returns a boolean if a field has been set.

### GetBody

`func (o *CustomerReviewAttributes) GetBody() string`

GetBody returns the Body field if non-nil, zero value otherwise.

### GetBodyOk

`func (o *CustomerReviewAttributes) GetBodyOk() (*string, bool)`

GetBodyOk returns a tuple with the Body field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBody

`func (o *CustomerReviewAttributes) SetBody(v string)`

SetBody sets Body field to given value.

### HasBody

`func (o *CustomerReviewAttributes) HasBody() bool`

HasBody returns a boolean if a field has been set.

### GetReviewerNickname

`func (o *CustomerReviewAttributes) GetReviewerNickname() string`

GetReviewerNickname returns the ReviewerNickname field if non-nil, zero value otherwise.

### GetReviewerNicknameOk

`func (o *CustomerReviewAttributes) GetReviewerNicknameOk() (*string, bool)`

GetReviewerNicknameOk returns a tuple with the ReviewerNickname field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReviewerNickname

`func (o *CustomerReviewAttributes) SetReviewerNickname(v string)`

SetReviewerNickname sets ReviewerNickname field to given value.

### HasReviewerNickname

`func (o *CustomerReviewAttributes) HasReviewerNickname() bool`

HasReviewerNickname returns a boolean if a field has been set.

### GetCreatedDate

`func (o *CustomerReviewAttributes) GetCreatedDate() time.Time`

GetCreatedDate returns the CreatedDate field if non-nil, zero value otherwise.

### GetCreatedDateOk

`func (o *CustomerReviewAttributes) GetCreatedDateOk() (*time.Time, bool)`

GetCreatedDateOk returns a tuple with the CreatedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCreatedDate

`func (o *CustomerReviewAttributes) SetCreatedDate(v time.Time)`

SetCreatedDate sets CreatedDate field to given value.

### HasCreatedDate

`func (o *CustomerReviewAttributes) HasCreatedDate() bool`

HasCreatedDate returns a boolean if a field has been set.

### GetTerritory

`func (o *CustomerReviewAttributes) GetTerritory() TerritoryCode`

GetTerritory returns the Territory field if non-nil, zero value otherwise.

### GetTerritoryOk

`func (o *CustomerReviewAttributes) GetTerritoryOk() (*TerritoryCode, bool)`

GetTerritoryOk returns a tuple with the Territory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTerritory

`func (o *CustomerReviewAttributes) SetTerritory(v TerritoryCode)`

SetTerritory sets Territory field to given value.

### HasTerritory

`func (o *CustomerReviewAttributes) HasTerritory() bool`

HasTerritory returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


