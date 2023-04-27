# CiProductResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CiProduct**](CiProduct.md) |  | 
**Included** | Pointer to [**[]CiProductsResponseIncludedInner**](CiProductsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCiProductResponse

`func NewCiProductResponse(data CiProduct, links DocumentLinks, ) *CiProductResponse`

NewCiProductResponse instantiates a new CiProductResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiProductResponseWithDefaults

`func NewCiProductResponseWithDefaults() *CiProductResponse`

NewCiProductResponseWithDefaults instantiates a new CiProductResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiProductResponse) GetData() CiProduct`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiProductResponse) GetDataOk() (*CiProduct, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiProductResponse) SetData(v CiProduct)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiProductResponse) GetIncluded() []CiProductsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiProductResponse) GetIncludedOk() (*[]CiProductsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiProductResponse) SetIncluded(v []CiProductsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiProductResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiProductResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiProductResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiProductResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


