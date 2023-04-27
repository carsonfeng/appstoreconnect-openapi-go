# CiProductAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**CreatedDate** | Pointer to **time.Time** |  | [optional] 
**ProductType** | Pointer to **string** |  | [optional] 

## Methods

### NewCiProductAttributes

`func NewCiProductAttributes() *CiProductAttributes`

NewCiProductAttributes instantiates a new CiProductAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiProductAttributesWithDefaults

`func NewCiProductAttributesWithDefaults() *CiProductAttributes`

NewCiProductAttributesWithDefaults instantiates a new CiProductAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *CiProductAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CiProductAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CiProductAttributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *CiProductAttributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetCreatedDate

`func (o *CiProductAttributes) GetCreatedDate() time.Time`

GetCreatedDate returns the CreatedDate field if non-nil, zero value otherwise.

### GetCreatedDateOk

`func (o *CiProductAttributes) GetCreatedDateOk() (*time.Time, bool)`

GetCreatedDateOk returns a tuple with the CreatedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCreatedDate

`func (o *CiProductAttributes) SetCreatedDate(v time.Time)`

SetCreatedDate sets CreatedDate field to given value.

### HasCreatedDate

`func (o *CiProductAttributes) HasCreatedDate() bool`

HasCreatedDate returns a boolean if a field has been set.

### GetProductType

`func (o *CiProductAttributes) GetProductType() string`

GetProductType returns the ProductType field if non-nil, zero value otherwise.

### GetProductTypeOk

`func (o *CiProductAttributes) GetProductTypeOk() (*string, bool)`

GetProductTypeOk returns a tuple with the ProductType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProductType

`func (o *CiProductAttributes) SetProductType(v string)`

SetProductType sets ProductType field to given value.

### HasProductType

`func (o *CiProductAttributes) HasProductType() bool`

HasProductType returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


