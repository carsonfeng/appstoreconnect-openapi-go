# AppEncryptionDeclarationDocument

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppEncryptionDeclarationDocumentAttributes**](AppEncryptionDeclarationDocumentAttributes.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppEncryptionDeclarationDocument

`func NewAppEncryptionDeclarationDocument(type_ string, id string, links ResourceLinks, ) *AppEncryptionDeclarationDocument`

NewAppEncryptionDeclarationDocument instantiates a new AppEncryptionDeclarationDocument object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEncryptionDeclarationDocumentWithDefaults

`func NewAppEncryptionDeclarationDocumentWithDefaults() *AppEncryptionDeclarationDocument`

NewAppEncryptionDeclarationDocumentWithDefaults instantiates a new AppEncryptionDeclarationDocument object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppEncryptionDeclarationDocument) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppEncryptionDeclarationDocument) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppEncryptionDeclarationDocument) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppEncryptionDeclarationDocument) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppEncryptionDeclarationDocument) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppEncryptionDeclarationDocument) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppEncryptionDeclarationDocument) GetAttributes() AppEncryptionDeclarationDocumentAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppEncryptionDeclarationDocument) GetAttributesOk() (*AppEncryptionDeclarationDocumentAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppEncryptionDeclarationDocument) SetAttributes(v AppEncryptionDeclarationDocumentAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppEncryptionDeclarationDocument) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetLinks

`func (o *AppEncryptionDeclarationDocument) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEncryptionDeclarationDocument) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEncryptionDeclarationDocument) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


