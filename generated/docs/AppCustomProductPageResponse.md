# AppCustomProductPageResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppCustomProductPage**](AppCustomProductPage.md) |  | 
**Included** | Pointer to [**[]AppCustomProductPagesResponseIncludedInner**](AppCustomProductPagesResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppCustomProductPageResponse

`func NewAppCustomProductPageResponse(data AppCustomProductPage, links DocumentLinks, ) *AppCustomProductPageResponse`

NewAppCustomProductPageResponse instantiates a new AppCustomProductPageResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCustomProductPageResponseWithDefaults

`func NewAppCustomProductPageResponseWithDefaults() *AppCustomProductPageResponse`

NewAppCustomProductPageResponseWithDefaults instantiates a new AppCustomProductPageResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppCustomProductPageResponse) GetData() AppCustomProductPage`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppCustomProductPageResponse) GetDataOk() (*AppCustomProductPage, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppCustomProductPageResponse) SetData(v AppCustomProductPage)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppCustomProductPageResponse) GetIncluded() []AppCustomProductPagesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppCustomProductPageResponse) GetIncludedOk() (*[]AppCustomProductPagesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppCustomProductPageResponse) SetIncluded(v []AppCustomProductPagesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppCustomProductPageResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppCustomProductPageResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppCustomProductPageResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppCustomProductPageResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


