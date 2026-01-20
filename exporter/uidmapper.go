package exporter

type UidMapping struct {
	m        map[uint32]uint32
	inScrape map[uint32]uint32
}

func NewUidMapping() *UidMapping {
	e := &UidMapping{
		m: make(map[uint32]uint32),
	}
	return e
}

func (mapping *UidMapping) StartScrape() {
	mapping.inScrape = make(map[uint32]uint32)
}

func (mapping *UidMapping) SimplifyUid(originalUid uint32) (mappedUid uint32) {
	if value, ok := mapping.m[originalUid]; ok {
		mapping.inScrape[originalUid] = value
		return value
	} else {
		value := mapping.allocateNew()
		mapping.inScrape[originalUid] = value
		mapping.m[originalUid] = value
		return value
	}
}

func (mapping *UidMapping) allocateNew() uint32 {
	var maximumValue uint32 = 0
	for _, v := range mapping.m {
		if maximumValue < v {
			maximumValue = v
		}
	}
	used_ids := make([]bool, maximumValue+1)
	for _, v := range mapping.m {
		used_ids[v] = true
	}
	for index, used := range used_ids[1:] {
		if !used {
			return uint32(index + 1)
		}
	}
	return maximumValue + 1
}

func (mapping *UidMapping) EndScrape() {
	mapping.m = mapping.inScrape
}
